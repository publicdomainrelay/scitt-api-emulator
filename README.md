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

The proxy server supports 3 tree algorithms currently:

- 'RFC9162_SHA256' uses the emulator server to create and verify Receipts as COSE Sign1 messages carrying [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) inclusion proofs, as described in Section 7 of [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html)
- 'CCF' uses the emulator server to create and verify receipts using the CCF tree algorithm. It predates COSE Receipts and produces a structure with no counterpart in the current documents; see [ADR 0005](docs/adrs/0005-cose-receipts.md)
- 'RKVST' uses the RKVST production SaaS server to create and verify  receipts using native Merkle trees

**Note:** _the emulator is for experimentation only and not recommended for production use._

### Start a Fake Emulated SCITT Service

1. Start the service, under the `/workspace` directory, using `RFC9162_SHA256`

    ```sh
    ./scitt-emulator.sh server --workspace workspace/ --tree-alg RFC9162_SHA256
    ```

1. The server is running at http://localhost:8000/ and uses the `workspace/` folder to store the service parameters and service state  
  **Note:** _The default port is `8000` but can be changed with the `--port` argument._
1. Start another shell to run the test scripts, leaving the above shell for diagnostic output
1. Skip to [Create Claims](#create-claims)

### Start an RKVST SCITT Proxy Service

1. Start the service, under the `/workspace` directory, using RKVST  
  The default port is `8000` but can be changed with the `--port` argument.

    ```sh
    ./scitt-emulator.sh server --workspace workspace/ --tree-alg RKVST
    ```

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
./scitt-emulator.sh server --workspace workspace/ --tree-alg RFC9162_SHA256 \
    --rate-limit-requests 100 --rate-limit-period 60
```

The following resources are emulator extensions or are deprecated, and are not
part of SCRAPI. See [docs/adrs/](docs/adrs/).

- `GET /entries/<entry_id>/statement` - retrieve the registered COSE_Sign1 Signed Statement. An emulator extension; SCRAPI has no resource for this.
- `GET /entries/<entry_id>/receipt` - deprecated, superseded by `GET /entries/<entry_id>`
- `GET /operations/<operation_id>` - deprecated, superseded by polling `GET /entries/<entry_id>`
- `GET /.well-known/transparency-configuration` - deprecated, superseded by `GET /.well-known/scitt-keys`

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
    "treeAlgorithm": "CCF",
    "signatureAlgorithm": "ES256",
    "insertPolicy": "*",
    "serviceCertificate": "-----BEGIN CERTIFICATE-----..."
}
```

`"signatureAlgorithm"` and `"serviceCertificate"` are additional parameters specific to the [`CCF` tree algorithm](https://ietf-scitt.github.io/draft-birkholz-scitt-receipts/draft-birkholz-scitt-receipts.html#name-additional-parameters).

To view the file:

```sh
cat workspace/service_parameters.json | jq
```

### COSE and CBOR Debugging

The following websites can be used to inspect COSE and CBOR files:

- [gluecose.github.io/cose-viewer](https://gluecose.github.io/cose-viewer/)
- [cbor.me](https://cbor.me/)

## Code Structure

`scitt_emulator/scitt.py` contains the core SCITT algorithms that are agnostic of a specific tree algorithm.

`scitt_emulator/rfc9162_sha256.py` is the implementation of the `RFC9162_SHA256` verifiable data structure, whose Receipts are COSE Sign1 messages as described in [Section 7 of RFC 9943](https://www.rfc-editor.org/rfc/rfc9943.html#name-receipts).

`scitt_emulator/ccf.py` is the implementation of the [CCF tree algorithm](https://ietf-scitt.github.io/draft-birkholz-scitt-receipts/draft-birkholz-scitt-receipts.html#name-ccf-tree-algorithm).
For each claim, a receipt is generated using a fake but valid Merkle tree that is independent of other submitted claims.
A real CCF service would maintain a single Merkle tree covering all submitted claims and auxiliary entries.

`scitt_emulator/rkvst.py` is a simple REST proxy that takes SCITT standard API calls and routes them through to the [RKVST production SaaS service](https://app.rkvst.io).
Each claim is stored in a Merkle tree underpinning a Quorum blockchain and receipts contain valid, verifiable inclusion proofs for the claim in that Merkle proof.
[More docs on receipts here](https://docs.rkvst.com/platform/overview/scitt-receipts/).

`scitt_emulator/server.py` is a simple Flask server that acts as a SCITT transparency service.

`scitt_emulator/client.py` is a CLI that supports creating claims, submitting claims to and retrieving receipts from the server, and verifying receipts.

In order to add a new tree algorithm, a file like `scitt_emulator/ccf.py` must be created and the containing class be added in `scitt_emulator/tree_algs.py`.

## Run Tests

```bash
./run-tests.sh
```

## Contributing

This project welcomes contributions and suggestions. Please see the [Contribution guidelines](CONTRIBUTING.md).
