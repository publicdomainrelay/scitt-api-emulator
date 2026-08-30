# SCITT API Interoperability Client

This repository contains the source code for the SCITT API interoperability client and sample emulator.

It is meant to allow experimenting with [SCITT](https://datatracker.ietf.org/wg/scitt/about/) APIs and formats and proving interoperability of implementations.

Note the SCITT standards are not yet fully published and are subject to change.
This repository aims to keep up with changes to the WG output as faithfully as possible but in the event of inconsistencies between this and the IETF WG documents, the IETF documents are primary.

## Prerequisites

The emulator assumes a Linux environment with Python 3.10 or higher.
On Ubuntu, run the following to install Python:

```sh
sudo apt install python3.10-venv
```

### Optional Dependencies

If you want to use conda, first install it:

- [Install Conda](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html)

You can get things setup with the following:

```sh
conda env create -f environment.yml
conda activate scitt
```

## Clone the Emulator

1. Clone the scitt-api-emulator repository and change into the scitt-api-emulator folder:

    ```sh
    git clone https://github.com/scitt-community/scitt-api-emulator.git
    ```

1. Move into the emulator director to utilize the local commands

    ```sh
    cd scitt-api-emulator
    ```

## Start the Proxy Server

The proxy server implements one verifiable data structure, `RFC9162_SHA256`:
it creates and verifies Receipts as COSE Sign1 messages carrying
[RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) inclusion proofs, as
described in Section 7 of [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html).

**Note:** _the emulator is for experimentation only and not recommended for production use._

### Start a Fake Emulated SCITT Service

1. Start the service, under the `/workspace` directory

    ```sh
    ./scitt-emulator.sh server --workspace workspace/
    ```

1. The server is running at http://localhost:8000/ and uses the `workspace/` folder to store the service parameters and service state  
  **Note:** _The default port is `8000` but can be changed with the `--port` argument._
1. Start another shell to run the test scripts, leaving the above shell for diagnostic output
1. Skip to [Create Claims](#create-claims)

### Executing Commands

The service has the following REST API:

The service implements the resources defined by
[draft-ietf-scitt-scrapi-11](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11):

- `GET /.well-known/scitt-keys` - the Receipt verification keys, as a COSE Key Set
- `GET /.well-known/scitt-keys/<kid_value>` - a single Receipt verification key
- `POST /entries` - register a COSE_Sign1 Signed Statement sent as the HTTP body. Responds `201` with the Receipt, or `202` if registration will take a while. Either way the `Location` header names the Receipt resource.
- `GET /entries/<entry_id>` - resolve the Receipt. `200` with the Receipt, `204` while registration is running, or `404` if there is none.

Errors are [RFC 9290](https://www.rfc-editor.org/rfc/rfc9290.html) Concise
Problem Details objects, served as `application/concise-problem-details+cbor`.

Rate limiting, required by Section 5.3 of the draft, is off by default. Enable
it with `--rate-limit-requests` and `--rate-limit-period` to exercise the `429`
response:

```sh
./scitt-emulator.sh server --workspace workspace/ \
    --rate-limit-requests 100 --rate-limit-period 60
```

By default the emulator accepts a Signed Statement without checking its
signature, for interoperability testing. RFC 9943 Section 6.3 requires a
Transparency Service to verify it; pass `--verify-signature` to turn that on.
With it set, the registration errors of Section 2.3.3 of the draft are
produced: `Bad Signature Algorithm`, `Payload Missing`, and `Rejected` for a
statement whose signature does not verify against its Issuer's key.

```sh
./scitt-emulator.sh server --workspace workspace/ --verify-signature
```

The following resource is an emulator extension and is not part of SCRAPI. See
[docs/adrs/](docs/adrs/).

- `GET /entries/<entry_id>/statement` - retrieve the registered COSE_Sign1 Signed Statement. An emulator extension; SCRAPI has no resource for this.

**Note:** The `submit-claim` and `retrieve-claim` commands use the default service URL `http://127.0.0.1:8000` which can be changed with the `--url` argument.
They can be used with the built-in server or an external service implementation.

### Create Signed Claims

1. Create a signed `json` claim with the payload: `{"sun": "yellow"}`, saving the formatted output to `claim.cose`

    ```sh
    ./scitt-emulator.sh client create-claim \
        --content-type application/json \
        --subject 'solar' \
        --payload '{"sun": "yellow"}' \
        --out claim.cose
    ```

    _**Note:** The emulator generates an ad-hoc key pair to sign the claim if
``--issuer`` and ``--public-key-pem`` are not given. See [Registration Policies](docs/registration_policies.md) docs for more deatiled examples_

2. View the signed claim by uploading `claim.cose` to one of the [CBOR or COSE Debugging Tools](#cose-and-cbor-debugging)

### Submit Claims and Retrieve Receipts

1. Submit the Signed Claim

    ```sh
    ./scitt-emulator.sh client submit-claim \
        --claim claim.cose \
        --out claim.receipt.cbor
    ```

1. View the response, noting the `Entry ID` value

    ```output
    Claim Registered:
        json:     {'entryId': '1'}
        Entry ID: 1
        Receipt:  ./claim.receipt.cbor
    ```

1. Save the entryId to an environment variable

   ```sh
   ENTRY_ID=<entryId>
   ```

### Retrieve Claims

1. Retrieve the claim, based on the ENTRY_ID set from the `submit-claim` command above

```sh
./scitt-emulator.sh client retrieve-claim \
  --entry-id $ENTRY_ID \
  --out claim.cose
```

This command sends the following request:

- `GET /entries/<entry_id>` to retrieve the claim.

### Retrieve Receipts

1. Replace the `<entryId>` with the value from the `submit-claim` command above

    ```sh
    ./scitt-emulator.sh client retrieve-receipt \
        --entry-id $ENTRY_ID \
        --out receipt.cbor
    ```

The `retrieve-receipt` command uses the default service URL `http://127.0.0.1:8000` which can be changed with the `--url` argument.
It can be used with the built-in server or an external service implementation.

This command sends the following request:

- `GET /entries/<entry_id>` to retrieve the receipt.

### Validate Receipts

```sh
./scitt-emulator.sh client verify-receipt \
    --claim claim.cose \
    --receipt claim.receipt.cbor \
    --service-parameters workspace/service_parameters.json
```

The `verify-receipt` command verifies a SCITT receipt given a SCITT claim and a service parameters file.
This command can be used to verify receipts generated by other implementations.

The `workspace/service_parameters.json` file gets created when starting a service using `./scitt-emulator.sh server`.
The format of this file is not standardized and is currently:

```json
{
    "serviceId": "emulator",
    "treeAlgorithm": "RFC9162_SHA256",
    "signatureAlgorithm": "ES256",
    "issuer": "transparency.example",
    "serviceCoseKey": "-----base64url COSE Key-----"
}
```

`"serviceCoseKey"` is the public COSE Key the service signs Receipts with, so a
Receipt can be verified from the service parameters alone.

To view the file:

```sh
cat workspace/service_parameters.json | jq
```

### COSE and CBOR Debugging

The following websites can be used to inspect COSE and CBOR files:

- [gluecose.github.io/cose-viewer](https://gluecose.github.io/cose-viewer/)
- [cbor.me](https://cbor.me/)

## Code Structure

`scitt_emulator/scitt.py` contains the core SCITT service: registration, Receipt
resolution, and the shared state machine.

`scitt_emulator/rfc9162_sha256.py` is the implementation of the `RFC9162_SHA256` verifiable data structure, whose Receipts are COSE Sign1 messages as described in [Section 7 of RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html#name-receipts).

`scitt_emulator/server.py` is a simple Flask server that acts as a SCITT transparency service.

`scitt_emulator/client.py` is a CLI that supports creating claims, submitting claims to and retrieving receipts from the server, and verifying receipts.

## Run Tests

```bash
./run-tests.sh
```

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).
