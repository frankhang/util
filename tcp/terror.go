package tcp

import (
	"github.com/frankhang/util/errors"
)

// Error code.
const (

	// CodeMissConnectionID indicates connection id is missing.
	CodeMissConnectionID errors.ErrCode = 1

	CodeAccessDenied errors.ErrCode = 2
)

// Error classes.
const (
//ClassAutoid ErrClass = iota + 1
//ClassDDL

)

// Global error instances.
var (
	ErrPeerHost = errors.ClassServer.New(CodeAccessDenied, "peer host error for addr: '%-.64s'")
)

var errClz2Str = map[errors.ErrClass]string{

}

func init() {
	for k, v := range errors.ErrClz2Str {
		errClz2Str[k] = v
	}
}
