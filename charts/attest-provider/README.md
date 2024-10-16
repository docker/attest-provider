## Parameters

|Parameter|Description|Default|
|:-|:-|:-|
|image|provider image to run|`docker/attest-provider:0.0.8`|
|certDir|mount path to use for TLS certificates|`/certs`|
|clientCAFile|optional mount path for gatekeeper client certificate (mTLS)|`/tmp/gatekeeper/ca.crt`|
|port|port for provider service|`8090`|
|handlerTimeout|timeout in seconds for provider HTTP handler|`25`|
|replicas|number of provider replicas in deployment|`1`|
|serviceAccountName|name of service account to attach to provider pods|``|
|tufRoot|name of embedded Docker TUF root to use for client (`dev`, `staging`, `prod`)|`prod`|
|tufMetadataSource|URI for TUF metadata (registry or http source)|`registry-1.docker.io/docker/tuf-metadata`|
|tufTargetsSource|URI for TUF targets (registry or http source)|`registry-1.docker.io/docker/tuf-targets`|
|attestationStyle|lookup attestations from image index (`attached`) or `referrers`|`referrers`|
|provider.timeout|timeout in seconds for gatekeeper external data request|`30`|
|provider.tls.caBundle|base64 encoded CA cert for provider|`""`|
|parameters|additional parameters to pass to the policy implementation|`""`|
