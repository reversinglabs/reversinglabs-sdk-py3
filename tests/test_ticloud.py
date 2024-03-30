import pytest
import requests
from ReversingLabs.SDK.ticloud import TiCloudAPI, CLASSIFICATIONS, AVAILABLE_PLATFORMS, RHA1_TYPE_MAP, resolve_hash_type
from ReversingLabs.SDK.helper import WrongInputError, BadGatewayError


EXPECTED_PLATFORMS = ("windows7", "windows10", "macos11", "windows11", "linux")
EXPECTED_RHA1_TYPES = {
	"PE": "pe01",
	"PE+": "pe01",
	"PE16": "pe01",
	"PE32": "pe01",
	"PE32+": "pe01",
	"MachO32 Big": "macho01",
	"MachO32 Little": "macho01",
	"MachO64 Big": "macho01",
	"MachO64 Little": "macho01",
	"ELF32 Big": "elf01",
	"ELF32 Little": "elf01",
	"ELF64 Big": "elf01",
	"ELF64 Little": "elf01"
}


def test_classifications():
	assert "KNOWN" in CLASSIFICATIONS, "Are you sure that KNOWN should be removed from allowed classifications?"
	assert "GOODWARE" not in CLASSIFICATIONS, "Are you sure that GOODWARE should be in allowed classifications?"


def test_platforms():
	assert "macos_11" not in AVAILABLE_PLATFORMS, "Did we start using macos_11 in cloud classifications?"

	for platform in EXPECTED_PLATFORMS:
		assert platform in AVAILABLE_PLATFORMS, "Are you sure some of the existing platforms needs to be removed?"


def test_rha1_types():
	for rha1_type in EXPECTED_RHA1_TYPES:
		assert rha1_type in RHA1_TYPE_MAP, "Are you sure some of the existing RHA1 types need to be changed or removed?"


def test_ticloud_object():
	valid_host = "some.host"
	invalid_host = "http://some.host"
	username = "u/username"
	password = "password"

	cloud_obj = TiCloudAPI(
		host=valid_host,
		username=username,
		password=password
	)

	assert cloud_obj._host == f"https://{valid_host}"

	with pytest.raises(WrongInputError, match=r"Unsupported protocol definition"):
		TiCloudAPI(host=invalid_host, username=username, password=password)

	resp = requests.Response()
	resp.status_code = 502

	with pytest.raises(BadGatewayError) as e:
		cloud_obj._raise_on_error(response=resp)
		assert e.value.response_object, "The _raise_on_error method did not assign the response object."


def test_hash_resolving():
	same_hash_types = [
		"5377d0ed664246a604363f90a2764aa10fa63ad0",
		"21841b32c6165b27dddbd4d6eb3a672defe54271",
		"efabc8b39de9d1f136abc48dc6e47f30a2ce9245"
	]
	various_hash_types = [
		"5377d0ed664246a604363f90a2764aa10fa63ad0",
		"00f8cd09187d311707b52a1c52018e7cfb5f2f78e47bf9200f16281098741422",
		"efabc8b39de9d1f136abc48dc6e47f30a2ce9245"
	]

	assert resolve_hash_type(sample_hashes=same_hash_types) == "sha1"

	with pytest.raises(WrongInputError, match=r"Hash on position 1 is a/an sha256"):
		resolve_hash_type(sample_hashes=various_hash_types)
