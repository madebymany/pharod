package main

import (
	"testing"
)

type stringFuncExpectation struct {
	in      string
	expects string
}

func TestDnsNameFromContainerName(t *testing.T) {
	expectations := []stringFuncExpectation{
		stringFuncExpectation{in: "pharod_db_1", expects: "pharod-db-1"},
		stringFuncExpectation{in: "/pharod_db_1__", expects: "pharod-db-1"},
		stringFuncExpectation{in: "/pharod_db__1.yes", expects: "pharod-db-1-yes"},
		stringFuncExpectation{in: "ph!@£$arod_db_1", expects: "ph-arod-db-1"},
	}

	for _, ex := range expectations {
		actual := dnsNameFromContainerName(ex.in)
		if actual != ex.expects {
			t.Logf("expected '%s', actual '%s'", ex.expects, actual)
			t.Fail()
		}
	}
}
