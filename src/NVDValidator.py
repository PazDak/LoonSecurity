import re

from .NVDApi import NvdApi

class NVDValidator:
    CVE_REGEX = r'^CVE-\d{4}-\d{4,7}'

    def __init__(self, api_key=None, retry_count=3, dict_caching=True, dict_caching_max_age=3600):
        """
        :param api_key: NVD API key
        :param retry_count: Number of times to retry
        :param dict_caching: Whether to cache data, defaults to True
        :param dict_caching_max_age: Max age in seconds for a record, defaults to 3600
        """
        self.nvd_api = NvdApi(api_key, retry_count, dict_caching, dict_caching_max_age)

    def embed_details(self, item: dict) -> None:
        """
        Searches for references for CVEs and embeds directly in the DICT the CVE Details
        :param item: DICT object containing CVE_IDs
        :return: None
        """
        self._search_keys(item, [], embed=True)

    def search_dict_cves(self, item: dict, details: bool) -> list[tuple]:
        """
        Searches for
        :param item:
        :param details:
        :return: list of Tuples in the format (Key, CVE_ID, Details)
        """
        response = self._search_keys(item, [], embed=False)
        response_l = []
        for item in response:
            if details:
                item = item + (self.nvd_api.get_cve_detail(cve_id=item[1]),)
            else:
                item = item + ({},)
            response_l.append(item)
        return response_l

    def _search_keys(self, key: dict, response: list, embed: bool) -> list[tuple]:
        """
        Recursively search for Keys and Values matching NVD Data
        :param key: Dict Object
        :param response:
        :return:
        """
        keys = list(key.keys())
        for item in keys:
            this_item = key[item]
            if type(this_item) is dict:
                self._search_keys(this_item, response, embed)
            elif type(this_item) is list:
                for _item in this_item:
                    _item_tuple = self._search_keys(_item, response, embed)
            elif type(this_item) is str:
                if re.findall(self.CVE_REGEX, str(this_item).upper()):
                    if embed:
                        self._add_cve_details_item(key, this_item, ['cve', 'meta', 'vuln_check'])
                    response.append((item, this_item))
            return response

    def _add_cve_details_item(self, item: dict, cve_id: str, keys: list) -> None:
        if 'loon_sec' not in item.keys():
            item['loon_sec'] = {
                'cve_details': {}
            }
        cve_details = item['loon_sec'].get(cve_id, None)
        if cve_details is None:
            cve_details = {}
            item['loon_sec']['cve_details'][cve_id] = cve_details
            if 'cve' in keys:
                cve_details['cve'] = self.nvd_api.get_cve_detail(cve_id)

