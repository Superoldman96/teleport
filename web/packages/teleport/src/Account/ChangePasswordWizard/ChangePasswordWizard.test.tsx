/**
 * Teleport
 * Copyright (C) 2024 Gravitational, Inc.
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

import { render, screen } from 'design/utils/testing';
import React from 'react';

import { within } from '@testing-library/react';
import { userEvent, UserEvent } from '@testing-library/user-event';

import auth, { MfaChallengeScope } from 'teleport/services/auth/auth';

import { MfaChallengeResponse } from 'teleport/services/mfa';

import {
  ChangePasswordWizardProps,
  createReauthOptions,
} from './ChangePasswordWizard';

import { ChangePasswordWizard } from '.';

const dummyChallengeResponse: MfaChallengeResponse = {
  webauthn_response: {
    id: 'cred-id',
    type: 'public-key',
    extensions: {
      appid: true,
    },
    rawId: 'rawId',
    response: {
      authenticatorData: 'authenticatorData',
      clientDataJSON: 'clientDataJSON',
      signature: 'signature',
      userHandle: 'userHandle',
    },
  },
};
let user: UserEvent;
let onSuccess: jest.Mock;

function twice(arr) {
  return [...arr, ...arr];
}

// Repeat devices twice to make sure we support multiple devices of the same
// type and purpose.
const deviceCases = {
  all: twice([
    { type: 'totp', usage: 'mfa' },
    { type: 'webauthn', usage: 'mfa' },
    { type: 'webauthn', usage: 'passwordless' },
  ]),
  authApps: twice([{ type: 'totp', usage: 'mfa' }]),
  mfaDevices: twice([{ type: 'webauthn', usage: 'mfa' }]),
  passkeys: twice([{ type: 'webauthn', usage: 'passwordless' }]),
};

function TestWizard(props: Partial<ChangePasswordWizardProps> = {}) {
  return (
    <ChangePasswordWizard
      auth2faType={'optional'}
      passwordlessEnabled={true}
      devices={deviceCases.all}
      onClose={() => {}}
      onSuccess={onSuccess}
      {...props}
    />
  );
}

beforeEach(() => {
  user = userEvent.setup();
  onSuccess = jest.fn();

  jest.spyOn(auth, 'getMfaChallenge').mockResolvedValueOnce(undefined);
  jest
    .spyOn(auth, 'getMfaChallengeResponse')
    .mockResolvedValueOnce(dummyChallengeResponse);
  jest.spyOn(auth, 'changePassword').mockResolvedValueOnce(undefined);
});

afterEach(jest.resetAllMocks);

describe('with passwordless reauthentication', () => {
  async function reauthenticate() {
    render(<TestWizard />);

    const reauthenticateStep = within(
      screen.getByTestId('reauthenticate-step')
    );
    await user.click(reauthenticateStep.getByText('Passkey'));
    await user.click(reauthenticateStep.getByText('Next'));
    expect(auth.getMfaChallenge).toHaveBeenCalledWith({
      scope: MfaChallengeScope.CHANGE_PASSWORD,
      userVerificationRequirement: 'required',
    });
    expect(auth.getMfaChallengeResponse).toHaveBeenCalled();
  }

  it('changes password', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).toHaveBeenCalledWith({
      oldPassword: '',
      newPassword: 'new-pass1234',
      secondFactorToken: '',
      webauthnResponse: dummyChallengeResponse.webauthn_response,
    });
    expect(onSuccess).toHaveBeenCalled();
  });

  it('cancels changing password', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Back'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('validates the password form', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass123'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass123'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(changePasswordStep.getByLabelText('New Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('New Password')
    ).toHaveAccessibleDescription('Enter at least 12 characters');

    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(changePasswordStep.getByLabelText('Confirm Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('Confirm Password')
    ).toHaveAccessibleDescription('Password does not match');
  });
});

describe('with WebAuthn MFA reauthentication', () => {
  async function reauthenticate() {
    render(<TestWizard />);

    const reauthenticateStep = within(
      screen.getByTestId('reauthenticate-step')
    );
    await user.click(reauthenticateStep.getByText('MFA Device'));
    await user.click(reauthenticateStep.getByText('Next'));
    expect(auth.getMfaChallenge).toHaveBeenCalledWith({
      scope: MfaChallengeScope.CHANGE_PASSWORD,
      userVerificationRequirement: 'discouraged',
    });
  }

  it('changes password', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('Current Password'),
      'current-pass'
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).toHaveBeenCalledWith({
      oldPassword: 'current-pass',
      newPassword: 'new-pass1234',
      secondFactorToken: '',
      webauthnResponse: dummyChallengeResponse.webauthn_response,
    });
    expect(onSuccess).toHaveBeenCalled();
  });

  it('cancels changing password', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Back'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('validates the password form', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass123'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass123'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(changePasswordStep.getByLabelText('New Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('New Password')
    ).toHaveAccessibleDescription('Enter at least 12 characters');
    expect(changePasswordStep.getByLabelText('Current Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('Current Password')
    ).toHaveAccessibleDescription('Current Password is required');

    await user.type(
      changePasswordStep.getByLabelText('Current Password'),
      'current-pass'
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(
      changePasswordStep.getByLabelText('Confirm Password')
    ).toHaveAccessibleDescription('Password does not match');
  });
});

describe('with OTP MFA reauthentication', () => {
  async function reauthenticate() {
    render(<TestWizard />);

    const reauthenticateStep = within(
      screen.getByTestId('reauthenticate-step')
    );
    await user.click(reauthenticateStep.getByText('Authenticator App'));
    await user.click(reauthenticateStep.getByText('Next'));
    expect(auth.getMfaChallenge).not.toHaveBeenCalled();
  }

  it('changes password', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('Current Password'),
      'current-pass'
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText(/Authenticator Code/),
      '654321'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).toHaveBeenCalledWith({
      oldPassword: 'current-pass',
      newPassword: 'new-pass1234',
      secondFactorToken: '654321',
    });
    expect(onSuccess).toHaveBeenCalled();
  });

  it('cancels changing password', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Back'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('validates the password form', async () => {
    await reauthenticate();
    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass123'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass123'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(changePasswordStep.getByLabelText('New Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('New Password')
    ).toHaveAccessibleDescription('Enter at least 12 characters');
    expect(changePasswordStep.getByLabelText('Current Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('Current Password')
    ).toHaveAccessibleDescription('Current Password is required');
    expect(
      changePasswordStep.getByLabelText('Authenticator Code')
    ).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('Authenticator Code')
    ).toHaveAccessibleDescription('Authenticator code is required');

    await user.type(
      changePasswordStep.getByLabelText('Authenticator Code'),
      '654321'
    );
    await user.type(
      changePasswordStep.getByLabelText('Current Password'),
      'current-pass'
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(changePasswordStep.getByLabelText('Confirm Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('Confirm Password')
    ).toHaveAccessibleDescription('Password does not match');
  });
});

describe('without reauthentication', () => {
  it('changes password', async () => {
    render(<TestWizard auth2faType="off" passwordlessEnabled={false} />);

    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('Current Password'),
      'current-pass'
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.getMfaChallenge).not.toHaveBeenCalled();
    expect(auth.changePassword).toHaveBeenCalledWith({
      oldPassword: 'current-pass',
      newPassword: 'new-pass1234',
      webauthnResponse: undefined,
      secondFactorToken: '',
    });
    expect(onSuccess).toHaveBeenCalled();
  });

  it('cancels changing password', async () => {
    render(<TestWizard auth2faType="off" passwordlessEnabled={false} />);

    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Cancel'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
  });

  it('validates the password form', async () => {
    render(<TestWizard auth2faType="off" passwordlessEnabled={false} />);

    const changePasswordStep = within(
      screen.getByTestId('change-password-step')
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass123'
    );
    await user.type(
      changePasswordStep.getByLabelText('Confirm Password'),
      'new-pass123'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(changePasswordStep.getByLabelText('New Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('New Password')
    ).toHaveAccessibleDescription('Enter at least 12 characters');
    expect(changePasswordStep.getByLabelText('Current Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('Current Password')
    ).toHaveAccessibleDescription('Current Password is required');

    await user.type(
      changePasswordStep.getByLabelText('Current Password'),
      'current-pass'
    );
    await user.type(
      changePasswordStep.getByLabelText('New Password'),
      'new-pass1234'
    );
    await user.click(changePasswordStep.getByText('Save Changes'));
    expect(auth.changePassword).not.toHaveBeenCalled();
    expect(onSuccess).not.toHaveBeenCalled();
    expect(changePasswordStep.getByLabelText('Confirm Password')).toBeInvalid();
    expect(
      changePasswordStep.getByLabelText('Confirm Password')
    ).toHaveAccessibleDescription('Password does not match');
  });
});

test.each`
  auth2faType   | passwordless | deviceCase      | methods
  ${'otp'}      | ${false}     | ${'all'}        | ${['otp']}
  ${'off'}      | ${false}     | ${'all'}        | ${[]}
  ${'optional'} | ${false}     | ${'all'}        | ${['mfaDevice', 'otp']}
  ${'on'}       | ${false}     | ${'all'}        | ${['mfaDevice', 'otp']}
  ${'webauthn'} | ${false}     | ${'all'}        | ${['mfaDevice']}
  ${'optional'} | ${true}      | ${'all'}        | ${['passwordless', 'mfaDevice', 'otp']}
  ${'on'}       | ${true}      | ${'all'}        | ${['passwordless', 'mfaDevice', 'otp']}
  ${'webauthn'} | ${true}      | ${'all'}        | ${['passwordless', 'mfaDevice']}
  ${'optional'} | ${true}      | ${'authApps'}   | ${['otp']}
  ${'optional'} | ${true}      | ${'mfaDevices'} | ${['mfaDevice']}
  ${'optional'} | ${true}      | ${'passkeys'}   | ${['passwordless']}
`(
  'createReauthOptions: auth2faType=$auth2faType, passwordless=$passwordless, devices=$deviceCase',
  ({ auth2faType, passwordless, methods, deviceCase }) => {
    const devices = deviceCases[deviceCase];
    const reauthMethods = createReauthOptions(
      auth2faType,
      passwordless,
      devices
    ).map(o => o.value);
    expect(reauthMethods).toEqual(methods);
  }
);
