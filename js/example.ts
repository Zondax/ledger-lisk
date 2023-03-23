import Transport from "@ledgerhq/hw-transport-node-hid";

import { LiskApp } from "./src";

async function main() {
  const transport = await Transport.create();
  const app = new LiskApp(transport);
  const indexes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9];
  const time = new Date().getTime();
  const result = await app.getMultipleAddresses(indexes);
  console.log(result);
  console.log(new Date().getTime() - time);
}

main();
