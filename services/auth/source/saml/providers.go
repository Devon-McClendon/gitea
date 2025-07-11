// Copyright 2021 The Gitea Authors. All rights reserved.
// SPDX-License-Identifier: MIT

package saml

import "html/template"

// Provider is an interface for describing a single SAML Identity Provider
type Provider interface {
	Name() string
	DisplayName() string
	IconHTML(size int) template.HTML
}
