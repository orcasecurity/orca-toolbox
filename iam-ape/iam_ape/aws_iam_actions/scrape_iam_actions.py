import json
import logging
import os
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
    data: Dict[str, Any] = defaultdict(lambda: defaultdict(dict))

    logger.info("Updating AWS IAM actions database...")
    for link in tqdm.tqdm(all_links, ncols=70):
        try:
            soup = get_soup(base_url + link[2:])
            # Avoids 'NoneType' object has no attribute 'string' (example: https://docs.aws.amazon.com/service-authorization/latest/reference/list_awsiot1-click.html)
            if soup.find("code") is None:
                continue
            service_prefix = soup.find("code").string
            tables = soup.find_all("div", class_="table-contents")
            for table in tables:
                headers = [
                    str(x).lower().replace("<th>", "").replace("</th>", "")
                    for x in table.find_all("th")
                ]
                if not all(
                    [header in headers for header in ("actions", "description")]
                ):
                    continue

                rowspan = 1
                for row in table.find_all("tr"):
                    if rowspan > 1:
                        rowspan -= 1
                        continue
                    rowspan = 1

                    all_cells = row.find_all("td")
                    if len(all_cells) == 0:
                        continue

                    if "rowspan" in all_cells[0].attrs:
                        rowspan = int(all_cells[0].attrs["rowspan"])

                    action = all_cells[0].text.strip().split(" ")[0]
                    description = all_cells[1].string
                    access_level = all_cells[2].string

                    data[service_prefix][action]["description"] = description
                    data[service_prefix][action]["access"] = access_level

        except AttributeError as e:
            logger.error(f"Error occurred while processing {link} - {e}")
            continue

    logger.info("Done!")

    tmpf = os.path.join(tempfile.gettempdir(), os.urandom(24).hex())
    with open(tmpf, "w+") as f:
        json.dump(data, f, indent=2)
        f.flush()
        with tarfile.open(actions_json_location, "w:gz") as tar:
            tar.add(f.name, arcname="actions.json")
    os.remove(tmpf)

    return 0


if __name__ == "__main__":
    exit(scrape_iam_actions())
