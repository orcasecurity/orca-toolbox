#!/bin/bash

shopt -s compat43 2>/dev/null
reset=`tput sgr0`
blue_bg=`tput setab 4`
white=`tput setaf 7`
red_bg=`tput setab 1`
bold=`tput bold`

extract_info1() {
        zone=($(gcloud compute instances list --filter $1 --format json | jq -r '.[].zone' | cut -d '/' -f 9))
        insta_svc_act=($(gcloud compute instances describe $1 --zone $zone --format json | jq -r '.serviceAccounts' | grep "email" | cut -d '"' -f 4))
        }

extract_info2() {
        role_svc_act=( $(gcloud projects get-iam-policy $1 --flatten="bindings[].members" --format=json --filter="bindings.members:$insta_svc_act" | jq -r '.[].bindings.role' | tail -n +1 | awk {'print $1'}) )
        scope=($(gcloud compute instances describe $2 --zone $zone --format json | jq -r '.serviceAccounts[].scopes[]'))
        }

check_is_project_has_svc_act() {
        svc_act=$(gcloud iam service-accounts list --format json | jq -r '.[].email')
        if [[ "$svc_act" = "" ]]; then
                echo "  [-] The project $1 has no service account" | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo '' | tee -a $out_file
                continue
        fi
        echo'' | tee -a $out_file
        }

check_is_instance_has_svc_act() {
        if [[ "$insta_svc_act" = "" ]]; then
                echo "  [-] The instance $1 has no service account" | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo '' | tee -a $out_file
                continue
        else
                echo "  [-] Instance $1 is using the following service account: $insta_svc_act" | tee -a $out_file
        fi
        }

check_is_instance_svc_act_has_roles() {
        if [[ "$role_svc_act" != "" ]]; then
                echo "  [-] The service account has the following roles: ${role_svc_act[@]}" | tee -a $out_file
        else
                echo "  [-] No roles configured..." | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo "" | tee -a $out_file
                continue
        fi
}

check_instance_cloud_api_access_scope() {
        if [[ $scope == *"devstorage.read_only"* ]] || [[ $scope == *"devstorage.read_write"* ]] || [[ $scope == *"devstorage.full_control"* ]] || [[ $scope == *"cloud-platform"* ]]; then
                echo "  [-] The instance has sufficient cloud API access scope" | tee -a $out_file
        else
                echo "  [-] The instance has no sufficient cloud API access scope" | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo '' | tee -a $out_file
                continue
        fi
        }

check_is_instance_svc_act_has_needed_roles() {
        for r in "${role_svc_act[@]}"
                do
                        right_role=$(gcloud iam roles describe $r | grep -w "storage.objects.get")
                        if [[ $right_role == *"storage.objects.get" ]]; then
                                echo "  [-] The service account role $r has the permission storage.objects.get" | tee -a $out_file
                                echo "${red_bg} ${white} ${bold}[+] WARNING: The instance $1 can read all storage in the project $2!${reset}" | tee -a $out_file
                                echo "" | tee -a $out_file
                                break
                        else
                                continue
                        fi
                done
}

if  ! which gcloud > /dev/null; then
   echo -e "${red_bg} ${white} gcloud not found! Please install gcloud and then run the script \c ${reset}"
   echo ''
   exit
fi

if  ! which jq > /dev/null; then
   echo -e "${red_bg} ${white} jq not found! Please install jq and then run the script \c ${reset}"
   echo ''
   exit
fi

if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        echo "Usage: `basename $0` -o <output_file.txt>"
        exit 0
fi

if [[ "$1" == "-o" ]]; then
        touch $2
        out_file=$2
else
        touch "results.txt"
        out_file="results.txt"
fi

token=$(gcloud auth print-access-token)

if [[ -n ${token} ]]
then
        auth_act=$(gcloud config list account --format "value(core.account)")
        echo "${red_bg}${white}${bold}Authenticated with the account $auth_act${reset}"  | tee -a $out_file
        echo ''
else
        gcloud auth login
        auth_act=$(gcloud config list account --format "value(core.account)")
        echo "${red_bg}${white}${bold}Authenticated with the account $auth_act${reset}" | tee -a $out_file
        echo ''
fi

echo ''  | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo "| GCP Storage Explorer                     |" | tee -a $out_file
echo "| Author: Liat Vaknin @ Orca Security      |" | tee -a $out_file
echo "| https://github.com/ElLicho007            |" | tee -a $out_file
printf "| %-40s |\n" "`date`" | tee -a $out_file
echo "| Starting....                             |" | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo '' | tee -a $out_file
echo '' | tee -a $out_file

echo "${blue_bg}${white}All available projects: ${reset}"  | tee -a $out_file
gcloud projects list  | tee -a $out_file
echo ''  | tee -a $out_file

echo "${blue_bg}${white}Select project to check or ALL: ${reset}" | tee -a $out_file
read selected_proj
echo $selected_proj >> $out_file
echo '' | tee -a $out_file

if [[ $selected_proj == "ALL" ]] || [[ $selected_proj == "All" ]] || [[ $selected_proj == "all" ]]
then
        proj=( $(gcloud projects list | tail -n +2 | awk {'print $1'}) )
else
        proj=$selected_proj
fi

for i in  "${proj[@]}"
        do
                echo "${blue_bg}${white}[*] Inspecting now project $i ${reset}" | tee -a $out_file
                gcloud config set project $i  | tee -a $out_file

                check_is_project_has_svc_act $i
                        
                echo "${blue_bg}${white}All instances in project $i: ${reset}" | tee -a $out_file
                gcloud compute instances list --filter="(-status=terminated)" | tee -a $out_file
                echo '' | tee -a $out_file
                
                echo "${blue_bg}${white}Select instance to check or ALL: ${reset}" | tee -a $out_file
                read selected_instance
                echo $selected_instance >> $out_file
                echo '' | tee -a $out_file
                
                if [[ $selected_instance == "ALL" ]] || [[ $selected_instance == "All" ]] || [[ $selected_instance == "all" ]]
                then
                        insta=($(gcloud compute instances list --filter="(-status=terminated)" | tail -n +2 | awk {'print $1'}))
                else
                        insta=$selected_instance
                fi

                for j in "${insta[@]}"
                        do
                                echo "${blue_bg}${white}[*] Inspecting now instance $j ${reset}" | tee -a $out_file

                                extract_info1 $j
                                                                        
                                check_is_instance_has_svc_act $j

                                extract_info2 $i $j

                                check_is_instance_svc_act_has_roles

                                check_instance_cloud_api_access_scope
                                
                                check_is_instance_svc_act_has_needed_roles $j $i
                       done
        done

echo '' | tee -a $out_file
echo '' | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo "| GCP Storage Explorer                     |" | tee -a $out_file
printf "| %-40s |\n" "`date`" | tee -a $out_file
echo "| Finished                                 |" | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo '' | tee -a $out_file
echo '' | tee -a $out_file