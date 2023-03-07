import json
import logging
import tarfile
import tempfile
from collections import defaultdict
from typing import Any, Dict

import requests
import tqdm  # type: ignore
from bs4 import BeautifulSoup  # type: ignore

from iam_ape.consts import actions_json_location

logger = logging.getLogger("IAM-APE:updater")
base_url = "https://docs.aws.amazon.com/service-authorization/latest/reference/"


def get_soup(url: str) -> BeautifulSoup:
    html_doc = requests.get(url).content.decode("utf-8")
    return BeautifulSoup(html_doc, "html.parser")


def scrape_iam_actions() -> int:
    soup = get_soup(base_url + "reference_policies_actions-resources-contextkeys.html")
    all_a = soup.find_all("a")
    all_links = [
        a.get("href") for a in all_a if a.get("href", "").startswith("./list_")
    ]
    data: Dict[str, Any] = {}

    logger.info("Updating AWS IAM actions database...")
    for link in tqdm.tqdm(all_links, ncols=70):
        try:
            soup = get_soup(base_url + link[2:])
            service_prefix = soup.find("code").string
            data[service_prefix] = defaultdict(dict)
            table = soup.find("table")
            table_rows = table.find_all("tr")
            for row in table_rows[1:]:
                all_cells = row.find_all("td")

                try:
                    action = all_cells[0].find("a", href=True).get_text()
                except AttributeError:  # AWS doing AWS things
                    continue

                if desc := all_cells[1].string:
                    data[service_prefix][action]["description"] = desc
                else:
                    continue

                data[service_prefix][action]["access"] = all_cells[2].string

        except AttributeError as e:
            logger.error(f"Error occurred while processing {link} - {e}")
            raise e

    logger.info("Done!")

    with tempfile.NamedTemporaryFile("w+") as f:
        json.dump(data, f, indent=2)
        f.flush()

        with tarfile.open(actions_json_location, "w:gz") as tar:
            tar.add(f.name, arcname="actions.json")

    return 0


if __name__ == "__main__":
    exit(scrape_iam_actions())