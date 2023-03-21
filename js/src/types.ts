export interface ResponseBase {
  error_message: string;
  return_code: number;
}

export interface ResponseAddress extends ResponseBase {
  pubKey: string;
  address: string;
}

export interface ResponseVersion extends ResponseBase {
  device_locked: boolean;
  major: number;
  minor: number;
  patch: number;
  test_mode: boolean;
}

export interface ResponseAppInfo extends ResponseBase {
  appName: string;
  appVersion: string;
  flagLen: number;
  flagsValue: number;
  flagRecovery: boolean;
  flagSignedMcuCode: boolean;
  flagOnboarded: boolean;
  flagPINValidated: boolean;
}

export interface ResponseDeviceInfo extends ResponseBase {
  targetId: string;
  seVersion: string;
  flag: string;
  mcuVersion: string;
}

export interface ResponseSign extends ResponseBase {
  signature: Buffer;
}
