package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
)

const securityListRuleLimit = 200

type config struct {
	OCIDFile           string
	ReplaceCIDRFile    string
	AdditionalCIDRFile string
	IncludeCurrentIP   bool
	PublicIPURL        string
	UpdatedFile        string
	Scope              string
	ReplaceAllIngress  bool
	DryRun             bool
	ConfigPath         string
	Profile            string
	ReportFile         string
	BackupDir          string
	RestoreBackup      string
	HTTPTimeout        time.Duration
	RequestTimeout     time.Duration
}

type operation struct {
	SecurityListOCID string
	Region           string
	Direction        string
	RuleIndex        int
	Protocol         string
	OldCIDR          string
	NewCIDR          string
	Status           string
	Timestamp        time.Time
	ErrorMessage     string
}

type backupSnapshot struct {
	Version          int                        `json:"version"`
	CapturedAt       time.Time                  `json:"capturedAt"`
	SecurityListOCID string                     `json:"securityListOcid"`
	Region           string                     `json:"region"`
	ETag             string                     `json:"etag"`
	IngressRules     []core.IngressSecurityRule `json:"ingressRules"`
	EgressRules      []core.EgressSecurityRule  `json:"egressRules"`
}

type securityListClient interface {
	GetSecurityList(context.Context, core.GetSecurityListRequest) (core.GetSecurityListResponse, error)
	UpdateSecurityList(context.Context, core.UpdateSecurityListRequest) (core.UpdateSecurityListResponse, error)
}

func main() {
	os.Exit(run())
}

func run() int {
	cfg, showHelp, err := parseFlags()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 2
	}
	if showHelp {
		return 0
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.RestoreBackup != "" {
		if err := restoreSnapshot(ctx, cfg); err != nil {
			fmt.Fprintln(os.Stderr, "ERROR:", err)
			return 1
		}
		return 0
	}

	replacements, currentCIDR, err := loadReplacementCIDRs(ctx, cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	if currentCIDR != "" {
		if err := os.WriteFile(cfg.UpdatedFile, []byte(currentCIDR+"\n"), 0600); err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: write current CIDR file: %v\n", err)
			return 1
		}
	}

	targets, err := readCIDRFile(cfg.ReplaceCIDRFile, !cfg.ReplaceAllIngress)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	targetSet := makeStringSet(targets)

	ocids, err := readValueFile(cfg.OCIDFile, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}

	report, err := newReport(cfg.ReportFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		return 1
	}
	defer report.Close()

	failures := 0
	for _, ocid := range uniqueStrings(ocids) {
		select {
		case <-ctx.Done():
			fmt.Fprintln(os.Stderr, "Interrupted")
			return 130
		default:
		}

		ops, processErr := processSecurityList(ctx, cfg, ocid, targetSet, replacements)
		for _, op := range ops {
			if err := report.Write(op); err != nil {
				fmt.Fprintln(os.Stderr, "ERROR: write report:", err)
				return 1
			}
		}
		if processErr != nil {
			failures++
			fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", ocid, processErr)
		}
	}

	if err := report.Flush(); err != nil {
		fmt.Fprintln(os.Stderr, "ERROR: flush report:", err)
		return 1
	}
	fmt.Printf("Completed: report=%s failures=%d dry-run=%t\n", cfg.ReportFile, failures, cfg.DryRun)
	if failures > 0 {
		return 1
	}
	return 0
}

func parseFlags() (config, bool, error) {
	var cfg config
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.StringVar(&cfg.OCIDFile, "ocid-file", "security_list_ocids.txt", "file containing Security List OCIDs")
	fs.StringVar(&cfg.ReplaceCIDRFile, "replace-cidr-file", "replace_cidrs.txt", "CIDRs whose matching rules will be expanded")
	fs.StringVar(&cfg.AdditionalCIDRFile, "additional-cidr-file", "additional_cidrs.txt", "additional replacement CIDRs, one per line")
	fs.BoolVar(&cfg.IncludeCurrentIP, "include-current-ip", true, "put the current public IPv4 /32 first in the replacement list")
	fs.StringVar(&cfg.PublicIPURL, "public-ip-url", "https://api.ipify.org", "HTTPS endpoint returning the current public IPv4 address")
	fs.StringVar(&cfg.UpdatedFile, "updated-file", "updated.txt", "file receiving the detected current CIDR")
	fs.StringVar(&cfg.Scope, "update", "both", "update scope: ingress, egress, or both")
	fs.BoolVar(&cfg.ReplaceAllIngress, "replace-all-ingress", false, "expand every CIDR_BLOCK ingress rule; ignores replace-cidr-file for ingress")
	fs.BoolVar(&cfg.DryRun, "dry-run", true, "preview without changing OCI")
	fs.StringVar(&cfg.ConfigPath, "config", "", "OCI config path (default: ~/.oci/config)")
	fs.StringVar(&cfg.Profile, "profile", "DEFAULT", "OCI config profile")
	fs.StringVar(&cfg.ReportFile, "report-file", "report.csv", "CSV report path")
	fs.StringVar(&cfg.BackupDir, "backup-dir", "backups", "directory for JSON snapshots created before an update")
	fs.StringVar(&cfg.RestoreBackup, "restore-backup", "", "restore one JSON snapshot instead of performing replacement")
	fs.DurationVar(&cfg.HTTPTimeout, "http-timeout", 10*time.Second, "public-IP HTTP timeout")
	fs.DurationVar(&cfg.RequestTimeout, "request-timeout", 45*time.Second, "timeout for each OCI request sequence")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `OCI Security List Multi-CIDR Updater

Each matching Security List rule is expanded into equivalent rules. The current
public IPv4 /32 is first, followed by unique CIDRs from --additional-cidr-file.

Usage:
  %s [flags]

`, filepath.Base(os.Args[0]))
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, true, nil
		}
		return cfg, false, err
	}
	cfg.Scope = strings.ToLower(strings.TrimSpace(cfg.Scope))
	if cfg.Scope != "ingress" && cfg.Scope != "egress" && cfg.Scope != "both" {
		return cfg, false, fmt.Errorf("--update must be ingress, egress, or both")
	}
	if cfg.ReplaceAllIngress && cfg.Scope == "egress" {
		return cfg, false, fmt.Errorf("--replace-all-ingress cannot be used with --update=egress")
	}
	if !cfg.IncludeCurrentIP && strings.TrimSpace(cfg.AdditionalCIDRFile) == "" && cfg.RestoreBackup == "" {
		return cfg, false, fmt.Errorf("no replacement source: enable --include-current-ip or provide --additional-cidr-file")
	}
	if cfg.RestoreBackup != "" && cfg.DryRun {
		fmt.Println("Restore preview only: use --dry-run=false to apply the snapshot.")
	}
	if cfg.ConfigPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return cfg, false, fmt.Errorf("resolve home directory: %w", err)
		}
		cfg.ConfigPath = filepath.Join(home, ".oci", "config")
	}
	return cfg, false, nil
}

func processSecurityList(parent context.Context, cfg config, ocid string, targets map[string]struct{}, replacements []string) ([]operation, error) {
	region, err := extractRegion(ocid)
	if err != nil {
		return []operation{errorOperation(ocid, "", "INVALID_OCID", err)}, err
	}
	client, err := newOCIClient(cfg.ConfigPath, cfg.Profile, region)
	if err != nil {
		return []operation{errorOperation(ocid, region, "CLIENT_ERROR", err)}, err
	}
	ctx, cancel := context.WithTimeout(parent, cfg.RequestTimeout)
	defer cancel()

	getResp, err := client.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: common.String(ocid)})
	if err != nil {
		return []operation{errorOperation(ocid, region, "GET_FAILED", err)}, err
	}

	ingress := getResp.IngressSecurityRules
	egress := getResp.EgressSecurityRules
	var changes []operation
	if cfg.Scope == "ingress" || cfg.Scope == "both" {
		ingress, changes = expandIngressRules(ocid, region, ingress, targets, replacements, cfg.ReplaceAllIngress)
	}
	if cfg.Scope == "egress" || cfg.Scope == "both" {
		var egressChanges []operation
		egress, egressChanges = expandEgressRules(ocid, region, egress, targets, replacements)
		changes = append(changes, egressChanges...)
	}

	if reflect.DeepEqual(ingress, getResp.IngressSecurityRules) && reflect.DeepEqual(egress, getResp.EgressSecurityRules) {
		if len(changes) == 0 {
			changes = append(changes, operation{SecurityListOCID: ocid, Region: region, RuleIndex: -1, Status: "NO_CHANGES", Timestamp: time.Now().UTC()})
		}
		return changes, nil
	}
	if len(ingress) > securityListRuleLimit || len(egress) > securityListRuleLimit {
		err := fmt.Errorf("planned rules exceed OCI limit: ingress=%d/%d egress=%d/%d", len(ingress), securityListRuleLimit, len(egress), securityListRuleLimit)
		markOperations(changes, "LIMIT_EXCEEDED", err)
		return changes, err
	}
	if cfg.DryRun {
		markOperations(changes, "WOULD_UPDATE", nil)
		fmt.Printf("[DRY-RUN] %s (%s): ingress=%d egress=%d\n", ocid, region, len(ingress), len(egress))
		return changes, nil
	}

	snapshot := backupSnapshot{
		Version: 1, CapturedAt: time.Now().UTC(), SecurityListOCID: ocid, Region: region,
		ETag: pointerValue(getResp.Etag), IngressRules: getResp.IngressSecurityRules, EgressRules: getResp.EgressSecurityRules,
	}
	backupPath, err := writeSnapshot(cfg.BackupDir, snapshot)
	if err != nil {
		markOperations(changes, "BACKUP_FAILED", err)
		return changes, fmt.Errorf("create mandatory backup: %w", err)
	}

	updateResp, err := client.UpdateSecurityList(ctx, core.UpdateSecurityListRequest{
		SecurityListId: common.String(ocid),
		IfMatch:        getResp.Etag,
		UpdateSecurityListDetails: core.UpdateSecurityListDetails{
			IngressSecurityRules: ingress,
			EgressSecurityRules:  egress,
		},
	})
	if err != nil {
		markOperations(changes, "UPDATE_FAILED", err)
		return changes, err
	}
	_ = updateResp
	markOperations(changes, "UPDATED", nil)
	fmt.Printf("[UPDATED] %s (%s): ingress=%d egress=%d backup=%s\n", ocid, region, len(ingress), len(egress), backupPath)
	return changes, nil
}

func expandIngressRules(ocid, region string, rules []core.IngressSecurityRule, targets map[string]struct{}, replacements []string, replaceAll bool) ([]core.IngressSecurityRule, []operation) {
	out := make([]core.IngressSecurityRule, 0, len(rules))
	generated := make([]core.IngressSecurityRule, 0)
	var ops []operation
	for i, rule := range rules {
		old, match := ingressCIDRMatch(rule, targets, replaceAll)
		if !match {
			out = append(out, rule)
			continue
		}
		added := 0
		for _, cidr := range replacements {
			clone := rule
			clone.Source = common.String(cidr)
			clone.SourceType = core.IngressSecurityRuleSourceTypeCidrBlock
			status := "PLANNED"
			if hasEquivalentIngressRule(rules, i, clone) || containsIngressRule(generated, clone) {
				status = "ALREADY_PRESENT"
			} else {
				out = append(out, clone)
				generated = append(generated, clone)
				added++
			}
			ops = append(ops, operation{SecurityListOCID: ocid, Region: region, Direction: "Ingress", RuleIndex: i, Protocol: pointerValue(rule.Protocol), OldCIDR: old, NewCIDR: cidr, Status: status, Timestamp: time.Now().UTC()})
		}
		if added == 0 {
			ops = append(ops, operation{SecurityListOCID: ocid, Region: region, Direction: "Ingress", RuleIndex: i, Protocol: pointerValue(rule.Protocol), OldCIDR: old, Status: "PLANNED_REMOVE_DUPLICATE", Timestamp: time.Now().UTC()})
		}
	}
	return out, ops
}

func expandEgressRules(ocid, region string, rules []core.EgressSecurityRule, targets map[string]struct{}, replacements []string) ([]core.EgressSecurityRule, []operation) {
	out := make([]core.EgressSecurityRule, 0, len(rules))
	generated := make([]core.EgressSecurityRule, 0)
	var ops []operation
	for i, rule := range rules {
		old, match := egressCIDRMatch(rule, targets)
		if !match {
			out = append(out, rule)
			continue
		}
		added := 0
		for _, cidr := range replacements {
			clone := rule
			clone.Destination = common.String(cidr)
			clone.DestinationType = core.EgressSecurityRuleDestinationTypeCidrBlock
			status := "PLANNED"
			if hasEquivalentEgressRule(rules, i, clone) || containsEgressRule(generated, clone) {
				status = "ALREADY_PRESENT"
			} else {
				out = append(out, clone)
				generated = append(generated, clone)
				added++
			}
			ops = append(ops, operation{SecurityListOCID: ocid, Region: region, Direction: "Egress", RuleIndex: i, Protocol: pointerValue(rule.Protocol), OldCIDR: old, NewCIDR: cidr, Status: status, Timestamp: time.Now().UTC()})
		}
		if added == 0 {
			ops = append(ops, operation{SecurityListOCID: ocid, Region: region, Direction: "Egress", RuleIndex: i, Protocol: pointerValue(rule.Protocol), OldCIDR: old, Status: "PLANNED_REMOVE_DUPLICATE", Timestamp: time.Now().UTC()})
		}
	}
	return out, ops
}

func ingressCIDRMatch(rule core.IngressSecurityRule, targets map[string]struct{}, replaceAll bool) (string, bool) {
	if rule.Source == nil || (rule.SourceType != "" && rule.SourceType != core.IngressSecurityRuleSourceTypeCidrBlock) {
		return "", false
	}
	canonical, err := canonicalPrefix(*rule.Source)
	if err != nil {
		return "", false
	}
	if replaceAll {
		return canonical, true
	}
	_, ok := targets[canonical]
	return canonical, ok
}

func egressCIDRMatch(rule core.EgressSecurityRule, targets map[string]struct{}) (string, bool) {
	if rule.Destination == nil || (rule.DestinationType != "" && rule.DestinationType != core.EgressSecurityRuleDestinationTypeCidrBlock) {
		return "", false
	}
	canonical, err := canonicalPrefix(*rule.Destination)
	if err != nil {
		return "", false
	}
	_, ok := targets[canonical]
	return canonical, ok
}

func hasEquivalentIngressRule(rules []core.IngressSecurityRule, excluded int, candidate core.IngressSecurityRule) bool {
	for i, rule := range rules {
		if i != excluded && reflect.DeepEqual(normalizeIngress(rule), normalizeIngress(candidate)) {
			return true
		}
	}
	return false
}

func hasEquivalentEgressRule(rules []core.EgressSecurityRule, excluded int, candidate core.EgressSecurityRule) bool {
	for i, rule := range rules {
		if i != excluded && reflect.DeepEqual(normalizeEgress(rule), normalizeEgress(candidate)) {
			return true
		}
	}
	return false
}

func containsIngressRule(rules []core.IngressSecurityRule, candidate core.IngressSecurityRule) bool {
	for _, rule := range rules {
		if reflect.DeepEqual(normalizeIngress(rule), normalizeIngress(candidate)) {
			return true
		}
	}
	return false
}

func containsEgressRule(rules []core.EgressSecurityRule, candidate core.EgressSecurityRule) bool {
	for _, rule := range rules {
		if reflect.DeepEqual(normalizeEgress(rule), normalizeEgress(candidate)) {
			return true
		}
	}
	return false
}

func normalizeIngress(rule core.IngressSecurityRule) core.IngressSecurityRule {
	if rule.Source != nil {
		if v, err := canonicalPrefix(*rule.Source); err == nil {
			rule.Source = common.String(v)
		}
	}
	if rule.SourceType == "" {
		rule.SourceType = core.IngressSecurityRuleSourceTypeCidrBlock
	}
	return rule
}

func normalizeEgress(rule core.EgressSecurityRule) core.EgressSecurityRule {
	if rule.Destination != nil {
		if v, err := canonicalPrefix(*rule.Destination); err == nil {
			rule.Destination = common.String(v)
		}
	}
	if rule.DestinationType == "" {
		rule.DestinationType = core.EgressSecurityRuleDestinationTypeCidrBlock
	}
	return rule
}

func loadReplacementCIDRs(ctx context.Context, cfg config) ([]string, string, error) {
	var values []string
	current := ""
	if cfg.IncludeCurrentIP {
		addr, err := fetchPublicIPv4(ctx, cfg.PublicIPURL, cfg.HTTPTimeout)
		if err != nil {
			return nil, "", err
		}
		current = netip.PrefixFrom(addr, 32).String()
		values = append(values, current)
	}
	if strings.TrimSpace(cfg.AdditionalCIDRFile) != "" {
		additional, err := readCIDRFile(cfg.AdditionalCIDRFile, false)
		if err != nil {
			return nil, "", err
		}
		values = append(values, additional...)
	}
	values = uniqueStrings(values)
	if len(values) == 0 {
		return nil, "", fmt.Errorf("replacement CIDR list is empty")
	}
	return values, current, nil
}

func fetchPublicIPv4(ctx context.Context, url string, timeout time.Duration) (netip.Addr, error) {
	if !strings.HasPrefix(strings.ToLower(url), "https://") {
		return netip.Addr{}, fmt.Errorf("public IP endpoint must use HTTPS")
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, url, nil)
	if err != nil {
		return netip.Addr{}, err
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("get current public IP: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("public IP endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read current public IP: %w", err)
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !addr.Is4() {
		return netip.Addr{}, fmt.Errorf("public IP endpoint did not return a valid IPv4 address")
	}
	return addr, nil
}

func readCIDRFile(path string, required bool) ([]string, error) {
	values, err := readValueFile(path, required)
	if err != nil {
		return nil, err
	}
	canonical := make([]string, 0, len(values))
	for line, value := range values {
		prefix, err := canonicalPrefix(value)
		if err != nil {
			return nil, fmt.Errorf("%s value %d (%q): %w", path, line+1, value, err)
		}
		canonical = append(canonical, prefix)
	}
	return uniqueStrings(canonical), nil
}

func readValueFile(path string, required bool) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !required && errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var values []string
	for _, raw := range strings.Split(string(data), "\n") {
		value := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if value == "" || strings.HasPrefix(value, "#") {
			continue
		}
		values = append(values, value)
	}
	if required && len(values) == 0 {
		return nil, fmt.Errorf("%s contains no values", path)
	}
	return values, nil
}

func canonicalPrefix(value string) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
	if err != nil {
		return "", fmt.Errorf("invalid CIDR: %w", err)
	}
	return prefix.Masked().String(), nil
}

func extractRegion(ocid string) (string, error) {
	parts := strings.Split(strings.TrimSpace(ocid), ".")
	if len(parts) < 5 || parts[0] != "ocid1" || parts[1] != "securitylist" || parts[3] == "" {
		return "", fmt.Errorf("invalid Security List OCID")
	}
	return parts[3], nil
}

func newOCIClient(configPath, profile, region string) (*core.VirtualNetworkClient, error) {
	provider, err := common.ConfigurationProviderFromFileWithProfile(configPath, profile, "")
	if err != nil {
		return nil, fmt.Errorf("load OCI profile %q: %w", profile, err)
	}
	client, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		return nil, fmt.Errorf("create OCI Virtual Network client: %w", err)
	}
	client.SetRegion(region)
	return &client, nil
}

func writeSnapshot(dir string, snapshot backupSnapshot) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	leaf := snapshot.SecurityListOCID
	if idx := strings.LastIndex(leaf, "."); idx >= 0 {
		leaf = leaf[idx+1:]
	}
	if len(leaf) > 24 {
		leaf = leaf[len(leaf)-24:]
	}
	name := fmt.Sprintf("security-list-%s-%s.json", leaf, snapshot.CapturedAt.Format("20060102T150405.000000000Z"))
	path := filepath.Join(dir, name)
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0600); err != nil {
		return "", err
	}
	return path, nil
}

func restoreSnapshot(parent context.Context, cfg config) error {
	data, err := os.ReadFile(cfg.RestoreBackup)
	if err != nil {
		return fmt.Errorf("read backup: %w", err)
	}
	var snapshot backupSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return fmt.Errorf("decode backup: %w", err)
	}
	if snapshot.Version != 1 || snapshot.SecurityListOCID == "" || snapshot.Region == "" {
		return fmt.Errorf("invalid or unsupported backup snapshot")
	}
	if len(snapshot.IngressRules) > securityListRuleLimit || len(snapshot.EgressRules) > securityListRuleLimit {
		return fmt.Errorf("snapshot exceeds OCI Security List rule limits")
	}
	client, err := newOCIClient(cfg.ConfigPath, cfg.Profile, snapshot.Region)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(parent, cfg.RequestTimeout)
	defer cancel()
	current, err := client.GetSecurityList(ctx, core.GetSecurityListRequest{SecurityListId: common.String(snapshot.SecurityListOCID)})
	if err != nil {
		return fmt.Errorf("get current Security List before restore: %w", err)
	}
	if cfg.DryRun {
		fmt.Printf("[DRY-RUN RESTORE] %s: ingress=%d egress=%d captured=%s\n", snapshot.SecurityListOCID, len(snapshot.IngressRules), len(snapshot.EgressRules), snapshot.CapturedAt.Format(time.RFC3339))
		return nil
	}
	preRestore := backupSnapshot{
		Version: 1, CapturedAt: time.Now().UTC(), SecurityListOCID: snapshot.SecurityListOCID,
		Region: snapshot.Region, ETag: pointerValue(current.Etag),
		IngressRules: current.IngressSecurityRules, EgressRules: current.EgressSecurityRules,
	}
	preRestorePath, err := writeSnapshot(cfg.BackupDir, preRestore)
	if err != nil {
		return fmt.Errorf("create mandatory pre-restore backup: %w", err)
	}
	_, err = client.UpdateSecurityList(ctx, core.UpdateSecurityListRequest{
		SecurityListId: common.String(snapshot.SecurityListOCID),
		IfMatch:        current.Etag,
		UpdateSecurityListDetails: core.UpdateSecurityListDetails{
			IngressSecurityRules: snapshot.IngressRules,
			EgressSecurityRules:  snapshot.EgressRules,
		},
	})
	if err != nil {
		return fmt.Errorf("restore Security List: %w", err)
	}
	fmt.Printf("[RESTORED] %s from %s pre-restore-backup=%s\n", snapshot.SecurityListOCID, cfg.RestoreBackup, preRestorePath)
	return nil
}

type csvReport struct {
	file   *os.File
	writer *csv.Writer
}

func newReport(path string) (*csvReport, error) {
	file, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create report: %w", err)
	}
	report := &csvReport{file: file, writer: csv.NewWriter(file)}
	if err := report.writer.Write([]string{"SecurityListOCID", "Region", "Direction", "RuleIndex", "Protocol", "OldCIDR", "NewCIDR", "Status", "Timestamp", "ErrorMessage"}); err != nil {
		file.Close()
		return nil, err
	}
	return report, nil
}

func (r *csvReport) Write(op operation) error {
	return r.writer.Write([]string{op.SecurityListOCID, op.Region, op.Direction, fmt.Sprintf("%d", op.RuleIndex), op.Protocol, op.OldCIDR, op.NewCIDR, op.Status, op.Timestamp.Format(time.RFC3339Nano), op.ErrorMessage})
}

func (r *csvReport) Flush() error {
	r.writer.Flush()
	return r.writer.Error()
}

func (r *csvReport) Close() error {
	flushErr := r.Flush()
	closeErr := r.file.Close()
	return errors.Join(flushErr, closeErr)
}

func markOperations(ops []operation, status string, err error) {
	for i := range ops {
		if ops[i].Status == "ALREADY_PRESENT" && (status == "WOULD_UPDATE" || status == "UPDATED") {
			continue
		}
		ops[i].Status = status
		if err != nil {
			ops[i].ErrorMessage = err.Error()
		}
	}
}

func errorOperation(ocid, region, status string, err error) operation {
	return operation{SecurityListOCID: ocid, Region: region, RuleIndex: -1, Status: status, Timestamp: time.Now().UTC(), ErrorMessage: err.Error()}
}

func makeStringSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func pointerValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
