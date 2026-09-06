# Cloudflare AI Gateway and DUSK proof of concept

This adapter places DUSK immediately before a request is forwarded to Cloudflare AI Gateway. The caller supplies the existing DUSK gate function and the exact action proposed by the agent. Only an `ALLOW` decision is forwarded. `BLOCK` and `WOULD-BLOCK` fail closed without making a network request.

## Example

```python
from dusk.integrations.cloudflare import CloudflareGatewayClient

client = CloudflareGatewayClient(
    "https://gateway.ai.cloudflare.com/v1/<account>/<gateway>/<provider>",
    api_token=os.environ["CLOUDFLARE_API_TOKEN"],
)
response = client.forward(payload, action=proposed_action, gate=dusk_gate)
```

The endpoint must use HTTPS. Tokens are supplied at runtime and are never written to logs or evidence. The proof of concept uses a mock HTTP boundary in tests and does not claim production readiness, Cloudflare endorsement, or universal protection.
