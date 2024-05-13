"""
A Service to allow syncing of the NVD records to several Databases
"""
import requests


class NvdApi:
    cve_cache = {}

    def __init__(self, api_key=None, retry_count=3, dict_caching=True, dict_caching_max_age=3600):
        """
        Initialize the API Service class
        :param api_key: NVD API key
        :param retry_count: Number of times to retry
        :param dict_caching: Whether to cache data, defaults to True
        :param dict_caching_max_age: Max age in seconds for a record, defaults to 3600
        """
        self.headers = {
            'Content-Type': 'application/json'
        }
        if api_key is not None:
            self.headers['apiKey'] = api_key

        self.retry_count = retry_count
        self.dict_caching = dict_caching
        self.dict_caching_max_age = dict_caching_max_age
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def get_cve_detail(self, cve_id: str) -> dict:
        """
        Retrieve the details of a CVE based on its CVE-ID
        :param cve_id: STR of the CVE
        :return: DICT of the NVD Details
        """
        # First Check the Dict Cache
        if self.dict_caching:
            results = self._check_nvd_cache_cve(cve_id)
            if results is not None:
                return results

        url = f"{self.nvd_url}?cveId={cve_id}"
        attempt = 0

        while attempt < self.retry_count:
            try:
                attempt += 1
                response = requests.get(url, headers=self.headers)
                if response.status_code == 200:
                    r = response.json()
                    if r['resultsPerPage'] == 1:
                        if self.dict_caching:
                            self._cache_nvd_cache_cve(cve_id=cve_id, cve_details=r['vulnerabilities'][0])
                        return r['vulnerabilities'][0]
                    elif r['resultsPerPage'] == 0:
                        self._cache_nvd_cache_cve(cve_id=cve_id, cve_details={})
                        return {}
            except:
                pass
        return {}

    def _call_nvd_api(self, results_per_page=2000, start_index=0, filters=None, retry_count=2) -> dict:
        """
        Makes an API Call to the NVD V2 CVE Services
        :param results_per_page: Custom number of results per page
        :param start_index: int of the index to start the API call
        :param filters: dict with filters for the api
        :param retry_count: Number of times to retry
        :return: dict containing results
        """
        params = {
            'resultsPerPage': results_per_page,
            'startIndex': start_index
        }
        if filters is not None:
            for key in filters.keys():
                params[key] = filters[key]

        while retry_count > 0:
            response = requests.get(self.nvd_url, headers=self.headers, params=params)
            if response.status_code == 200:
                response_dict = response.json()
                if response_dict['resultsPerPage'] != response_dict['totalResults']:
                    print(f"{response_dict['totalResults']} {False}")
                return response.json()
            retry_count -= 1
        return {}

    def get_list_cves(self, filters: dict = None) -> dict:
        """
        Retrieve a list of CVEs based on Filters
        Valid Filters
        :param filters:
        :return:
        """
        valid_keys = {
            "lastModStartDate": {
                "format": "[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]",
                "type": "datetime",
                "required": False,
                "validator_function": "validate_date"
            },
            "lastModEndDate": {
                "format": "[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]",
                "type": "datetime",
                "required": False,
                "validator_function": "validate_date"
            },
            "pubStartDate": {
                "format": "[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]",
                "type": "datetime",
                "required": False,
                "validator_function": "validate_date"
            },
            "pubEndDate": {
                "format": "[YYYY][“-”][MM][“-”][DD][“T”][HH][“:”][MM][“:”][SS][Z]",
                "type": "datetime",
                "required": False,
                "validator_function": "validate_date"
            }
        }
        params = {}

        for key in valid_keys.keys():
            if key in filters:
                params[key] = filters[key]

        response = self._call_nvd_api(filters=params)
        if response['resultsPerPage'] == response['totalResults']:
            return response
        while len(response['vulnerabilities']) < response['totalResults']:
            r = self._call_nvd_api(filters=params, start_index=len(response['vulnerabilities'])-1)
            response['vulnerabilities'].extend(r['vulnerabilities'])
        response['vulnerabilities'] = self._dedup_cve_list(response['vulnerabilities'])
        return response

    @staticmethod
    def _dedup_cve_list(vulnerabilities):
        """
        Deduplicate CVEs from the list
        :param vulnerabilities:
        :return:
        """
        results = []
        results_cve_id = []
        for vulnerability in vulnerabilities:
            if vulnerability['cve']['id'] not in results_cve_id:
                results_cve_id.append(vulnerability['cve']['id'])
                results.append(vulnerability)
        return results

    def _check_nvd_cache_cve(self, cve_id: str) -> dict | None:
        """
        Checks if the cve is in the cache
        :param cve_id: STR of the CVE ID example CVE-2024-31497
        :return: Dict if it exists or a NONE object
        """
        if self.cve_cache.get(cve_id, None) is not None:
            print(f"found cve {cve_id}")
        return self.cve_cache.get(cve_id, None)

    def _cache_nvd_cache_cve(self, cve_id: str, cve_details: dict) -> None:
        """
        Adds a CVE Details to the CVE Cache
        :param cve_id: STR of the CVE ID Example: CVE-2024-31497
        :param cve_details: Dict of the CVE from NVD
        :return: None
        """
        self.cve_cache[cve_id] = cve_details
