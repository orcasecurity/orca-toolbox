#!/bin/bash

shopt -s compat43 2>/dev/null
reset=`tput sgr0`
blue_bg=`tput setab 4`
white=`tput setaf 7`
red_bg=`tput setab 1`
bold=`tput bold`

check_is_project_has_dflt_svc_act() {
        svc_act=$(gcloud iam service-accounts list --filter "Compute Engine default service account" --format json | jq -r '.[].email')
        if [[ "$svc_act" = "" ]]; then
                echo "  [-] No service account in project $1" | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo '' | tee -a $out_file
                continue
        fi
        echo "  [-] The default service account for project $i is: $svc_act" | tee -a $out_file
        }

check_is_dflt_svc_act_has_roles() {
        role_svc_act=$(gcloud projects get-iam-policy $1 --flatten="bindings[].members" --format=json --filter="bindings.members:$svc_act" | jq -r '.[].bindings.role')
        if [[ "$role_svc_act" != *"roles/editor"* ]]; then
                echo "  [-] No editor role found for the service account" | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo '' | tee -a $out_file
                continue
        else
                echo "  [-] The roles for the default service account are: $role_svc_act" | tee -a $out_file
                echo'' | tee -a $out_file
        fi
        }

check_is_instance_has_dflt_svc_act() {
        if [[ "$insta_svc_act" == "$svc_act" ]]; then
                echo "  [-] Instance $1 is using the default service account $svc_act" | tee -a $out_file
        else
                echo "  [-] Instance $1 is not using the default service account" | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo '' | tee -a $out_file
                continue
        fi
        }

check_instance_cloud_api_access_scope() {
        scope=($(gcloud compute instances describe $1 --zone $zone --format json | jq -r '.serviceAccounts[].scopes[]'))
        if [[ $scope == *"https://www.googleapis.com/auth/cloud-platform"* ]]; then
                echo "  [-] Instance $j has all cloud APIs access scope" | tee -a $out_file
                echo "${red_bg}${white}${bold}  [+] WARNING: The instance $1 can access ALL instances in the project $i!${reset}" | tee -a $out_file
                echo "${red_bg}${white}${bold}  [+] WARNING: From the instance $1 use the command gcloud compute ssh <target instance> to gain access!${reset}" | tee -a $out_file
                echo '' | tee -a $out_file
        else
                echo "  [-] No sufficient cloud API access scope" | tee -a $out_file
                echo "  [-] Moving on..." | tee -a $out_file
                echo '' | tee -a $out_file
        fi
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
        echo "${red_bg}${white}${bold}Authenticated with the account $auth_act${reset}" | tee -a $out_file
        echo ''
else
        gcloud auth login
        auth_act=$(gcloud config list account --format "value(core.account)")
        echo "${red_bg}${white}${bold}Authenticated with the account $auth_act${reset}" | tee -a $out_file
        echo ''
fi

echo '' | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo "| GCP Lateral Movement Detector            |" | tee -a $out_file
echo "| Author: Liat Vaknin @ Orca Security      |" | tee -a $out_file
echo "| https://github.com/ElLicho007            |" | tee -a $out_file
printf "| %-40s |\n" "`date`" | tee -a $out_file
echo "| Starting....                             |" | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo '' | tee -a $out_file
echo '' | tee -a $out_file

echo "${blue_bg}${white}All available projects: ${reset}" | tee -a $out_file
gcloud projects list | tee -a $out_file
echo '' | tee -a $out_file

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
                gcloud config set project $i | tee -a $out_file

                check_is_project_has_dflt_svc_act $i

                check_is_dflt_svc_act_has_roles $i

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

                                zone=($(gcloud compute instances list --filter $j --format json | jq -r '.[].zone' | cut -d '/' -f 9))
                                insta_svc_act=($(gcloud compute instances describe $j --zone $zone --format json | jq -r '.serviceAccounts' | grep "email" | cut -d '"' -f 4))

                                check_is_instance_has_dflt_svc_act $j

                                check_instance_cloud_api_access_scope $j $i

                       done
        done

echo '' | tee -a $out_file
echo '' | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo "| GCP Lateral Movement Detector            |" | tee -a $out_file
printf "| %-40s |\n" "`date`" | tee -a $out_file
echo "| Finished                                 |" | tee -a $out_file
echo "+------------------------------------------+" | tee -a $out_file
echo '' | tee -a $out_file
echo '' | tee -a $out_file