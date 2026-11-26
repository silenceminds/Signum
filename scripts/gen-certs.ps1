param(
    [string]$OutDir = "$PSScriptRoot\..\certs",
    [string]$Domain = "signum.local",
    [string]$Subdomain = "app.signum.local"
)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

# 1. Root CA
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes `
    -keyout "$OutDir\ca.key" -out "$OutDir\ca.crt" -days 365 `
    -subj "/CN=Signum Test CA" 2>$null

# 2. Edge Control & Public Server Cert (SAN: localhost, 127.0.0.1, *.$Domain)
$extFile = "$OutDir\edge_ext.cnf"
@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,DNS:*.$Domain,DNS:$Subdomain,IP:127.0.0.1
"@ | Set-Content -Path $extFile -Encoding Ascii

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes `
    -keyout "$OutDir\edge.key" -out "$OutDir\edge.csr" `
    -subj "/CN=*.$Domain" 2>$null

openssl x509 -req -in "$OutDir\edge.csr" -CA "$OutDir\ca.crt" -CAkey "$OutDir\ca.key" `
    -CAcreateserial -out "$OutDir\edge.crt" -days 365 -extfile $extFile 2>$null

# 3. Client mTLS Cert (bound to $Subdomain)
$cliExtFile = "$OutDir\client_ext.cnf"
@"
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=DNS:$Subdomain
"@ | Set-Content -Path $cliExtFile -Encoding Ascii

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes `
    -keyout "$OutDir\client.key" -out "$OutDir\client.csr" `
    -subj "/CN=$Subdomain" 2>$null

openssl x509 -req -in "$OutDir\client.csr" -CA "$OutDir\ca.crt" -CAkey "$OutDir\ca.key" `
    -CAcreateserial -out "$OutDir\client.crt" -days 365 -extfile $cliExtFile 2>$null

# 4. Compute SHA-256 SPKI pin of edge.crt (write DER to temp file to avoid PowerShell binary pipe mangling)
openssl x509 -in "$OutDir\edge.crt" -pubkey -noout -out "$OutDir\edge.pub.pem" 2>$null
openssl pkey -pubin -in "$OutDir\edge.pub.pem" -outform der -out "$OutDir\edge.spki.der" 2>$null
$spkiPin = (openssl dgst -sha256 -hex "$OutDir\edge.spki.der").Split(' ')[-1].Trim()
Remove-Item "$OutDir\edge.pub.pem", "$OutDir\edge.spki.der" -ErrorAction SilentlyContinue
$spkiPin | Set-Content -Path "$OutDir\edge.spki" -Encoding Ascii

Write-Output "Generated certs in $OutDir"
Write-Output "Edge SPKI SHA-256 Pin: $spkiPin"
