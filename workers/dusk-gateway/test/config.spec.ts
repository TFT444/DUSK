import { expect, it } from "vitest";

import config from "../../../wrangler.jsonc?raw";

it("defines the dusk Worker with observability", () => {
  expect(config).toContain('"name": "dusk"');
  expect(config).toContain('"main": "workers/dusk-gateway/src/index.ts"');
  expect(config).toContain('"enabled": true');
  expect(config).not.toContain("DUSK_GATEWAY_TOKEN=");
});
