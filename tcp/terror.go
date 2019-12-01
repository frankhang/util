// Copyright 2015 PingCAP, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// See the License for the specific language governing permissions and
// limitations under the License.

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
