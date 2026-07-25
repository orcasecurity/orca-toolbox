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

MIN_SERVICE_PAGES = 300


def get_soup(url: str) -> BeautifulSoup:
    return BeautifulSoup(requests.get(url).text, "html.parser")


def scrape_iam_actions() -> int:
    soup = get_soup(base_url + "reference_policies_actions-resources-contextkeys.html")
    all_a = soup.find_all("a")
    all_links = [
        a.get("href") for a in all_a if a.get("href", "").startswith("./list_")
    ]
    data: Dict[str, Any] = defaultdict(lambda: defaultdict(dict))

    logger.info("Updating AWS IAM actions database...")
    pages_with_actions = 0
    for link in tqdm.tqdm(all_links, ncols=70):
        try:
            soup = get_soup(base_url + link[2:])
            code = soup.find("code")
            service_prefix = code.string if code else None
            if not service_prefix:
                continue
            page_yielded_action = False
            for table in soup.find_all("div", class_="table-contents"):
                headers = [
                    th.get_text(strip=True).lower() for th in table.find_all("th")
                ]
                if not all(
                    col in headers for col in ("actions", "description", "access level")
                ):
                    continue
                action_idx = headers.index("actions")
                description_idx = headers.index("description")
                access_idx = headers.index("access level")

                for row in table.find_all("tr"):
                    all_cells = row.find_all("td")
                    if len(all_cells) != len(headers):
                        continue
                    action = all_cells[action_idx].get_text(strip=True).split(" ")[0]
                    data[service_prefix][action]["description"] = all_cells[
                        description_idx
                    ].get_text(strip=True)
                    data[service_prefix][action]["access"] = all_cells[
                        access_idx
                    ].get_text(strip=True)
                    page_yielded_action = True
            if page_yielded_action:
                pages_with_actions += 1

        except Exception as e:
            logger.error(f"Error occurred while processing {link} - {e}")
            continue

    if pages_with_actions < MIN_SERVICE_PAGES:
        raise RuntimeError(
            f"Only {pages_with_actions} service pages yielded actions (< {MIN_SERVICE_PAGES}); "
            "aborting so the bundled DB is not overwritten with a regressed crawl"
        )

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
