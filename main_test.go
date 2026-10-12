package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

const rootHelpHelperProcess = "OSINTSCAN_ROOT_HELP_HELPER"

func TestRootHelpUsesCobra(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=TestRootHelpHelperProcess")
	command.Env = append(os.Environ(), rootHelpHelperProcess+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("run root help: %v\n%s", err, output)
	}
	help := string(output)
	if !strings.Contains(help, "Usage:\n  osintscan [command]") {
		t.Fatalf("expected Cobra root help, got:\n%s", help)
	}
	if strings.Contains(help, "Usage of osintscan") {
		t.Fatalf("unexpected standard-library flag help:\n%s", help)
	}
}

func TestRootHelpHelperProcess(t *testing.T) {
	if os.Getenv(rootHelpHelperProcess) != "1" {
		return
	}
	os.Args = []string{"osintscan", "--help"}
	main()
}
