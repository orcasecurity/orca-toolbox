import json
import urllib3
import webbrowser
import requests
import argparse
import datetime
import sys
from tabulate import tabulate

class UnauthorizedError(Exception):
    def __init__(self, message="Invalid / Expired token"):
        self.message = message
        super().__init__(self.message)


BODY_DATA = json.dumps({
    'apiVersion': 'authorization.k8s.io/v1',
    'kind': 'SelfSubjectRulesReview',
    'spec': {
        'namespace': '*'
    }
})

BANNER = """
:'######::'##:::'##::'######:::'##:::::'###::::'##:::::::'##::::::::'##:::'######::'##::::'##:'########::'######::'##:::'##:
'##... ##:. ##:'##::'##... ##:'####:::'## ##::: ##::::::: ##:::::::'####:'##... ##: ##:::: ##: ##.....::'##... ##: ##::'##::
 ##:::..:::. ####::: ##:::..::. ##:::'##:. ##:: ##::::::: ##:::::::. ##:: ##:::..:: ##:::: ##: ##::::::: ##:::..:: ##:'##:::
. ######::::. ##::::. ######:::..:::'##:::. ##: ##::::::: ##::::::::..::: ##::::::: #########: ######::: ##::::::: #####::::
:..... ##:::: ##:::::..... ##::'##:: #########: ##::::::: ##::::::::'##:: ##::::::: ##.... ##: ##...:::: ##::::::: ##. ##:::
'##::: ##:::: ##::::'##::: ##:'####: ##.... ##: ##::::::: ##:::::::'####: ##::: ##: ##:::: ##: ##::::::: ##::: ##: ##:. ##::
. ######::::: ##::::. ######::. ##:: ##:::: ##: ########: ########:. ##::. ######:: ##:::: ##: ########:. ######:: ##::. ##:
:......::::::..::::::......::::..:::..:::::..::........::........:::..::::......:::..:::::..::........:::......:::..::::..::
"""

def print_banner():
    today = datetime.datetime.today().strftime("%a %b %d %H:%M:%S %Y")
    print('\033[92m' + BANNER)
    print(f'+------------------------------------------------+')
    print(f'-       Author: Roi Nisimi @ Orca Security       -')
    print(f'+------------------------------------------------+' + '\033[0m')
    print(flush=True)

def can_i_sys_all(cluster, token):
    urllib3.disable_warnings()

    headers = {
        'Authorization': f'Bearer {token}'
    }

    try:
        resp = requests.post(
            url=f'https://{cluster}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews',
            data=BODY_DATA, 
            headers=headers,
            verify=False,
            timeout=5
        )

        if 401 == resp.status_code:
            raise UnauthorizedError

        api_groups = [rule['apiGroups'] for rule in resp.json()['status']['resourceRules']] # results with a nested list. E.g [[''], ['authorization.k8s.io']] 
        if any(group not in ['authorization.k8s.io', 'authentication.k8s.io'] for group in [item for groups in api_groups for item in groups]): # flat the nested list
            return True    

    except UnauthorizedError as e:
        print(f'{cluster}'.ljust(17, ' ') + f'Failed due-to: {e}')
        sys.exit()

    except Exception as e:
        print(f'{cluster}'.ljust(17, ' ') + f'Failed due-to: {e}')

    return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-browser', action='store_true', help='Do not open the OAuth Playground in a web browser')
    args = parser.parse_args()
    
    print_banner()

    if not args.no_browser:
        webbrowser.open('https://developers.google.com/oauthplayground/')

    token = input('Paste your token: ')
    print()

    with open('clusters.txt', 'r') as f:
        clusters = f.read().split('\n')

    vulnerable_clusters = []
    for cluster in clusters:
        vulnerable_clusters.append(cluster) if can_i_sys_all(cluster, token) else None

    print(tabulate([[i + 1, ip] for i, ip in enumerate(vulnerable_clusters)],
        headers=['#', 'IP'],
        tablefmt='fancy_grid'))

if __name__ == '__main__':
    main()