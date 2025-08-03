# -*- coding: utf-8 -*-
#
# Copyright (C) 2025 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

import pytest
from src.views.fast_spdx3 import FastSPDX3
from src.controllers.packages import PackagesController
from src.controllers.vulnerabilities import VulnerabilitiesController
from src.controllers.assessments import AssessmentsController


@pytest.fixture
def spdx3_parser():
    """Create FastSPDX3 parser with fresh controllers."""
    controllers = {
        "packages": PackagesController(),
        "vulnerabilities": VulnerabilitiesController(PackagesController()),
        "assessments": AssessmentsController(
            PackagesController(),
            VulnerabilitiesController(PackagesController())
        )
    }
    return FastSPDX3(controllers)


class TestExtractCpes:
    """Test CPE extraction from SPDX elements."""

    def test_extract_valid_cpe23(self, spdx3_parser):
        """Test extracting valid CPE 2.3 identifiers."""
        element = {
            "externalIdentifier": [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*"
                }
            ]
        }
        result = spdx3_parser.extract_cpes(element)
        assert len(result) == 1
        assert "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*" in result

    def test_extract_cpe_with_different_format(self, spdx3_parser):
        """Test extracting CPE identifiers with different format."""
        element = {
            "externalIdentifier": [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:*:*:base-files:3.0.14:*:*:*:*:*:*:*"
                }
            ]
        }
        result = spdx3_parser.extract_cpes(element)
        assert len(result) == 1
        assert "cpe:2.3:*:*:base-files:3.0.14:*:*:*:*:*:*:*" in result

    def test_extract_cpes_no_external_identifier(self, spdx3_parser):
        """Test extracting CPEs when externalIdentifier is missing."""
        element = {"name": "test"}
        result = spdx3_parser.extract_cpes(element)
        assert result == []

    def test_extract_cpes_invalid_external_identifier_type(self, spdx3_parser):
        """Test extracting CPEs with invalid externalIdentifier type."""
        element = {
            "externalIdentifier": "not_a_list"
        }
        result = spdx3_parser.extract_cpes(element)
        assert result == []

    def test_extract_cpes_non_cpe_identifier(self, spdx3_parser):
        """Test extracting CPEs when identifier is not CPE type."""
        element = {
            "externalIdentifier": [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cve",
                    "identifier": "CVE-2022-28391"
                }
            ]
        }
        result = spdx3_parser.extract_cpes(element)
        assert result == []

    def test_extract_cpes_missing_identifier(self, spdx3_parser):
        """Test extracting CPEs when identifier field is missing."""
        element = {
            "externalIdentifier": [
                {
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cpe23",
                    # Missing identifier field
                }
            ]
        }
        result = spdx3_parser.extract_cpes(element)
        assert result == []


class TestExtractCveId:
    """Test CVE ID extraction from text strings."""

    def test_extract_valid_cve_id(self, spdx3_parser):
        """Test extracting valid CVE IDs."""
        assert spdx3_parser._extract_cve_id("CVE-2023-1234") == "CVE-2023-1234"
        result = spdx3_parser._extract_cve_id("CVE-2023-12345")
        assert result == "CVE-2023-12345"
        result = spdx3_parser._extract_cve_id("CVE-2021-44228")
        assert result == "CVE-2021-44228"

    def test_extract_cve_from_url(self, spdx3_parser):
        """Test extracting CVE IDs from URLs."""
        url = "https://cveawg.mitre.org/api/cve/CVE-2023-1234"
        assert spdx3_parser._extract_cve_id(url) == "CVE-2023-1234"

        url2 = "https://www.cve.org/CVERecord?id=CVE-2022-28391"
        assert spdx3_parser._extract_cve_id(url2) == "CVE-2022-28391"

        url3 = ("http://spdx.org/spdxdocs/linux-yocto/vulnerability/"
                "CVE-2021-44228")
        result = spdx3_parser._extract_cve_id(url3)
        assert result == "CVE-2021-44228"

    def test_extract_cve_invalid_format(self, spdx3_parser):
        """Test extracting CVE IDs with invalid formats."""
        assert spdx3_parser._extract_cve_id("CVE-23-1234") is None
        assert spdx3_parser._extract_cve_id("cve-2023-1234") is None
        assert spdx3_parser._extract_cve_id("CVE-2023-123") is None
        assert spdx3_parser._extract_cve_id("not-a-cve") is None

    def test_extract_cve_empty_input(self, spdx3_parser):
        """Test extracting CVE IDs from empty/None inputs."""
        assert spdx3_parser._extract_cve_id("") is None
        assert spdx3_parser._extract_cve_id(None) is None

    def test_extract_cve_with_surrounding_text(self, spdx3_parser):
        """Test extracting CVE IDs with surrounding text."""
        text = "This vulnerability CVE-2023-1234 affects the system"
        assert spdx3_parser._extract_cve_id(text) == "CVE-2023-1234"


class TestVersionDetection:
    """Test SPDX version detection and parsing capability."""

    def test_find_spdx_version_valid(self, spdx3_parser):
        """Test finding valid SPDX 3.x version."""
        spdx_doc = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1"
                }
            ]
        }
        assert spdx3_parser.find_spdx_version(spdx_doc) == "3.0.1"

    def test_find_spdx_version_missing_graph(self, spdx3_parser):
        """Test finding version when @graph is missing."""
        spdx_doc = {"name": "test"}
        assert spdx3_parser.find_spdx_version(spdx_doc) is None

    def test_could_parse_spdx_version_3(self, spdx3_parser):
        """Test that parser can handle SPDX 3.x versions."""
        spdx_doc = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "specVersion": "3.0.1"
                }
            ]
        }
        assert spdx3_parser.could_parse_spdx(spdx_doc) is True

    def test_could_parse_spdx_version_2(self, spdx3_parser):
        """Test that parser rejects SPDX 2.x versions."""
        spdx_doc = {
            "@graph": [
                {
                    "type": "CreationInfo",
                    "specVersion": "2.3"
                }
            ]
        }
        assert spdx3_parser.could_parse_spdx(spdx_doc) is False

    def test_could_parse_spdx_no_version(self, spdx3_parser):
        """Test parser behavior when no version is found."""
        spdx_doc = {"@graph": []}
        assert spdx3_parser.could_parse_spdx(spdx_doc) is False


class TestExtractPurl:
    """Test PURL extraction from SPDX elements."""

    def test_extract_purl_from_packageUrl(self, spdx3_parser):
        """Test extracting PURL from packageUrl field."""
        element = {
            "packageUrl": "pkg:rpm/redhat/curl@7.76.1"
        }
        result = spdx3_parser.extract_purl(element)
        assert result == "pkg:rpm/redhat/curl@7.76.1"

    def test_extract_purl_from_software_packageUrl(self, spdx3_parser):
        """Test extracting PURL from software_packageUrl field."""
        element = {
            "software_packageUrl": "pkg:npm/express@4.18.0"
        }
        result = spdx3_parser.extract_purl(element)
        assert result == "pkg:npm/express@4.18.0"

    def test_extract_purl_missing_fields(self, spdx3_parser):
        """Test extracting PURL when no PURL fields exist."""
        element = {
            "name": "test",
            "version": "1.0"
        }
        result = spdx3_parser.extract_purl(element)
        assert result is None


class TestConvertToPackage:
    """Test package object conversion from SPDX elements."""

    def test_convert_valid_package(self, spdx3_parser):
        """Test converting valid package element."""
        pkg_element = {
            "name": "binutils",
            "software_packageVersion": "2.38",
            "externalIdentifier": [
                {
                    "externalIdentifierType": "cpe23",
                    "identifier": "cpe:2.3:a:gnu:binutils:2.38:*:*:*:*:*:*:*"
                }
            ]
        }
        result = spdx3_parser._convert_to_package(pkg_element)
        assert result is not None
        assert result.name == "binutils"
        assert result.version == "2.38"
        assert len(result.cpe) > 0

    def test_convert_package_missing_name(self, spdx3_parser):
        """Test converting package with missing name."""
        pkg_element = {
            "software_packageVersion": "1.0"
        }
        result = spdx3_parser._convert_to_package(pkg_element)
        assert result is None

    def test_convert_package_missing_version(self, spdx3_parser):
        """Test converting package with missing version."""
        pkg_element = {
            "name": "test-package"
        }
        result = spdx3_parser._convert_to_package(pkg_element)
        assert result is None


class TestIsVexRelationship:
    """Test VEX relationship type detection."""

    def test_is_vex_not_affected_relationship(self, spdx3_parser):
        """Test detecting VEX not affected relationship."""
        rel = {"type": "security_VexNotAffectedVulnAssessmentRelationship"}
        assert spdx3_parser.is_vex_relationship(rel) is True

    def test_is_vex_affected_relationship(self, spdx3_parser):
        """Test detecting VEX affected relationship."""
        rel = {"type": "security_VexAffectedVulnAssessmentRelationship"}
        assert spdx3_parser.is_vex_relationship(rel) is True

    def test_is_vex_fixed_relationship(self, spdx3_parser):
        """Test detecting VEX fixed relationship."""
        rel = {"type": "security_VexFixedVulnAssessmentRelationship"}
        assert spdx3_parser.is_vex_relationship(rel) is True

    def test_is_not_vex_relationship(self, spdx3_parser):
        """Test detecting non-VEX relationship."""
        rel = {"type": "Relationship"}
        assert spdx3_parser.is_vex_relationship(rel) is False

    def test_is_vex_missing_type(self, spdx3_parser):
        """Test behavior when type field is missing."""
        rel = {"other": "field"}
        assert spdx3_parser.is_vex_relationship(rel) is False

    def test_is_vex_empty_type(self, spdx3_parser):
        """Test behavior with empty type field."""
        rel = {"type": ""}
        assert spdx3_parser.is_vex_relationship(rel) is False


class TestParseVexRelationship:
    """Test VEX relationship parsing logic."""

    def test_parse_not_affected_vex(self, spdx3_parser):
        """Test parsing not affected VEX relationship."""
        spdx3_parser.uri_to_package["http://package/uri"] = "package@1.0"

        element = {
            "from": "http://vuln/CVE-2022-28391",
            "to": ["http://package/uri"],
            "relationshipType": "doesNotAffect",
            "security_justificationType": "componentNotPresent",
            "security_impactStatement": "Component not present"
        }

        result = spdx3_parser._parse_vex_relationship(element)
        assert result is not None
        assert result.vuln_id == "CVE-2022-28391"
        assert result.status == "not_affected"
        assert result.justification == "component_not_present"
        assert result.impact_statement == "Component not present"

    def test_parse_affected_vex(self, spdx3_parser):
        """Test parsing affected VEX relationship."""
        spdx3_parser.uri_to_package["http://package/uri"] = "package@2.0"

        element = {
            "from": "http://vuln/CVE-2024-32928",
            "to": ["http://package/uri"],
            "relationshipType": "affects"
        }

        result = spdx3_parser._parse_vex_relationship(element)
        assert result is not None
        assert result.vuln_id == "CVE-2024-32928"
        assert result.status == "affected"

    def test_parse_fixed_vex(self, spdx3_parser):
        """Test parsing fixed VEX relationship."""
        spdx3_parser.uri_to_package["http://package/uri"] = "package@3.0"

        element = {
            "from": "http://vuln/CVE-2019-6293",
            "to": ["http://package/uri"],
            "relationshipType": "fixedIn"
        }

        result = spdx3_parser._parse_vex_relationship(element)
        assert result is not None
        assert result.vuln_id == "CVE-2019-6293"
        assert result.status == "fixed"

    def test_parse_vex_missing_from_field(self, spdx3_parser):
        """Test parsing VEX with missing from field."""
        element = {"to": ["http://package/uri"]}
        assert spdx3_parser._parse_vex_relationship(element) is None

    def test_parse_vex_missing_to_field(self, spdx3_parser):
        """Test parsing VEX with missing to field."""
        element = {"from": "http://vuln/CVE-2022-28391"}
        assert spdx3_parser._parse_vex_relationship(element) is None

    def test_parse_vex_invalid_to_field(self, spdx3_parser):
        """Test parsing VEX with invalid to field (not a list)."""
        element = {
            "from": "http://vuln/CVE-2022-28391",
            "to": "not_a_list"
        }
        assert spdx3_parser._parse_vex_relationship(element) is None

    def test_parse_vex_empty_to_list(self, spdx3_parser):
        """Test parsing VEX with empty to list."""
        element = {
            "from": "http://vuln/CVE-2022-28391",
            "to": []
        }
        assert spdx3_parser._parse_vex_relationship(element) is None

    def test_parse_vex_unknown_package_uri(self, spdx3_parser):
        """Test parsing VEX with unknown package URI."""
        element = {
            "from": "http://vuln/CVE-2022-28391",
            "to": ["http://unknown/package"]
        }
        assert spdx3_parser._parse_vex_relationship(element) is None

    def test_parse_vex_invalid_cve_format(self, spdx3_parser):
        """Test parsing VEX with invalid CVE format."""
        spdx3_parser.uri_to_package["http://package/uri"] = "package@1.0"

        element = {
            "from": "http://vuln/INVALID-CVE",
            "to": ["http://package/uri"],
            "relationshipType": "doesNotAffect"
        }
        assert spdx3_parser._parse_vex_relationship(element) is None
