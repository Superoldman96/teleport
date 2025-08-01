/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package clientcredentials

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/gravitational/trace"
	"golang.org/x/crypto/ssh"

	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/lib/tbot/bot"
	"github.com/gravitational/teleport/lib/tbot/identity"
	"github.com/gravitational/teleport/lib/tbot/internal/encoding"
)

const ServiceType = "unstable_client_credential"

var (
	_ client.Credentials = &UnstableConfig{}
)

// UnstableConfig is an experimental tbot output which is compatible with the
// client.Credential interface. This allows tbot to be used as an in-memory
// source of credentials for the Teleport API client and removes the need to
// write credentials to a filesystem.
//
// Unstable: no API stability promises are made for this struct and its methods.
// Available configuration options may change and the signatures of methods may
// be modified. This output is currently part of an experiment and could be
// removed in a future release.
type UnstableConfig struct {
	// Name of the service for logs and the /readyz endpoint.
	Name string `yaml:"name,omitempty"`

	mu     sync.Mutex
	facade *identity.Facade
	ready  chan struct{}
}

// GetName returns the user-given name of the service, used for validation purposes.
func (o *UnstableConfig) GetName() string {
	return o.Name
}

// Ready returns a channel which closes when the Output is ready to be used
// as a client credential. Using this as a credential before Ready closes is
// unsupported.
func (o *UnstableConfig) Ready() <-chan struct{} {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.ready == nil {
		o.ready = make(chan struct{})
		if o.facade != nil {
			close(o.ready)
		}
	}
	return o.ready
}

// Dialer implements the client.Credential interface. It does nothing.
func (o *UnstableConfig) Dialer(c client.Config) (client.ContextDialer, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return nil, trace.NotImplemented("no dialer")
}

// TLSConfig implements the client.Credential interface and return the
// tls.Config from the underlying identity.Facade.
func (o *UnstableConfig) TLSConfig() (*tls.Config, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.facade == nil {
		return nil, trace.BadParameter("credentials not yet ready")
	}
	return o.facade.TLSConfig()
}

// SSHClientConfig implements the client.Credential interface and return the
// ssh.ClientConfig from the underlying identity.Facade.
func (o *UnstableConfig) SSHClientConfig() (*ssh.ClientConfig, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.facade == nil {
		return nil, trace.BadParameter("credentials not yet ready")
	}
	return o.facade.SSHClientConfig()
}

// Expiry returns the credential expiry.
func (o *UnstableConfig) Expiry() (time.Time, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.facade == nil {
		return time.Time{}, false
	}
	return o.facade.Expiry()
}

// Facade returns the underlying facade
func (o *UnstableConfig) Facade() (*identity.Facade, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.facade == nil {
		return nil, trace.BadParameter("credentials not yet ready")
	}
	return o.facade, nil
}

// SetOrUpdateFacade sets up the underlying facade or updates it if it has
// already been created.
func (o *UnstableConfig) SetOrUpdateFacade(id *identity.Identity) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.facade == nil {
		if o.ready != nil {
			close(o.ready)
		}
		o.facade = identity.NewFacade(false, false, id)
		return
	}
	o.facade.Set(id)
}

// CheckAndSetDefaults checks and sets default values for the configuration.
func (o *UnstableConfig) CheckAndSetDefaults() error {
	return nil
}

// MarshalYAML enables the yaml package to correctly marshal the config
// as YAML including the type header.
func (o *UnstableConfig) MarshalYAML() (any, error) {
	type raw UnstableConfig
	return encoding.WithTypeHeader((*raw)(o), ServiceType)
}

// Type returns a human readable description of this output.
func (o *UnstableConfig) Type() string {
	return ServiceType
}

// GetCredentialLifetime returns the credential lifetime configuration.
func (o *UnstableConfig) GetCredentialLifetime() bot.CredentialLifetime {
	return bot.CredentialLifetime{}
}
