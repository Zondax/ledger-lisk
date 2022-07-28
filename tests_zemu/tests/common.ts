import { DeviceModel } from '@zondax/zemu'

const Resolve = require('path').resolve

export const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')
const APP_PATH_SP = Resolve('../app/output/app_s2.elf')

export const models: DeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
]

export const tx_message = "Just a dummy message to be signed"
export const tx_token_transfer = "0a05746f6b656e12087472616e73666572180220beb8f0fe2d2a20bfbef2a36e17ca75b66fd56adea8dd04ed234cd4188aca42fc8a7299d8eaadd8324d0a08000000020000000110ffffffffffffffffff011a1400b1182b317a82e4b9c4a54119ced29f19b496de22207765206861766520736f6d6520696e666f726d6174696f6e2069732068657265"
