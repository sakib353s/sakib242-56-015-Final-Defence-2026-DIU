/** expo-local-authentication wrapper — device credential / biometric gates. */
import * as LocalAuthentication from 'expo-local-authentication';

export interface BiometricCapability {
  hardware: boolean;
  enrolled: boolean;
}

export async function checkBiometrics(): Promise<BiometricCapability> {
  const hardware = (await LocalAuthentication.hasHardwareAsync()) === true;
  const enrolled = hardware && (await LocalAuthentication.isEnrolledAsync()) === true;
  return { hardware, enrolled };
}

/** Returns true only on successful authentication; 'cancel' counts as denial. */
export async function promptBiometric(reason: string): Promise<boolean> {
  const { hardware, enrolled } = await checkBiometrics();
  if (!hardware || !enrolled) return false;
  const res = await LocalAuthentication.authenticateAsync({
    promptMessage: reason,
    cancelLabel: 'ABORT',
    disableDeviceFallback: true,
  });
  return res.success === true;
}
