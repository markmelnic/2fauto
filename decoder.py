from base64 import b32encode, b64decode
from collections.abc import Generator
from typing import Any, Dict, List, Union
from urllib.parse import ParseResult, parse_qs, quote, urlencode, urlparse
from enums import Algorithm, DigitCount, OtpType
from protobuf import Payload


SCHEME = "otpauth-migration"
HOSTNAME = "offline"
PAYLOAD_MARK = "data"


def verify_migration(
    *,
    parsed_url: ParseResult,
    parsed_qs: Dict[str, Any],
) -> bool:
    return (
        parsed_url.scheme != SCHEME
        or parsed_url.hostname != HOSTNAME
        or PAYLOAD_MARK not in parsed_qs
        or not isinstance(parsed_qs[PAYLOAD_MARK], list)
    )


def decoded_data(data: List[str]) -> Generator:
    for data_item in data:
        yield b64decode(data_item)


def get_url_params(otp: Payload.OtpParameters) -> str:
    params: dict[str, Union[str, int]] = {}

    if otp.algorithm:
        params.update(algorithm=Algorithm.get(otp.algorithm, ""))
    if otp.digits:
        params.update(digits=DigitCount.get(otp.digits, ""))
    if otp.issuer:
        params.update(issuer=otp.issuer)
    if otp.secret:
        otp_secret = str(b32encode(otp.secret), "utf-8").replace("=", "")
        params.update(secret=otp_secret)

    return urlencode(params)


def get_otpauth_url(otp: Payload.OtpParameters) -> str:
    otp_type = OtpType.get(otp.type, "")
    otp_name = quote(otp.name)
    otp_params = get_url_params(otp)

    return f"otpauth://{otp_type}/{otp_name}?{otp_params}"


def validate_migration(migration: str) -> list[str]:
    url: ParseResult = urlparse(migration)
    qs: Dict[str, Any] = parse_qs(url.query)

    if verify_migration(parsed_url=url, parsed_qs=qs):
        raise Exception("Incorrect migration data")

    return qs[PAYLOAD_MARK]


def decode(migration_data: list[str]) -> list:
    items: list = []
    for payload in decoded_data(data=validate_migration(migration_data)):
        migration_payload = Payload()
        migration_payload.ParseFromString(payload)

        items.extend(migration_payload.otp_parameters)
    return items
