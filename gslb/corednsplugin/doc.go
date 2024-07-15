// Package corednsplugin is an adaptor which converts gslbcore.Core to a CoreDNS plugin.
//
// By using the adaptor, we can focus on the GSLB logic in gslbcore.Core, and
// split the DNS protocol details.
//
// Overview:
//   - `setup.go` is primarily about how to handle the custom directives in the
//     configuration file and configure `gslbcore.Config` accordingly.
//   - `handler.go` provides the CoreDNS plugin implementation. It focuses on
//     how to handle DNS requests and generate corresponding responses.
package corednsplugin
