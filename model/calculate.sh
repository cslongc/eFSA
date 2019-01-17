#!/bin/bash

File="statetransdelay.log"
mean=`awk '{TOTAL+=$1} END{printf("%.8f\n",TOTAL/NR)}' $File`
sdev=`awk -v imean=$mean '{TOTAL+=(imean-$1)^2} END{printf("%.8f",(TOTAL/FNR)^(1/2))}' $File`
echo "FSA/eFSA statetrans checking delay: mean:"$mean", standard dev:"$sdev

File="eventchecking.log"
mean=`awk '{TOTAL+=$1} END{printf("%.8f\n",TOTAL/NR)}' $File`
sdev=`awk -v imean=$mean '{TOTAL+=(imean-$1)^2} END{printf("%.8f",(TOTAL/FNR)^(1/2))}' $File`
echo "eFSA local event checking delay: mean:"$mean", standard dev:"$sdev

File="networkeventchecking.log"
mean=`awk '{TOTAL+=$1} END{printf("%.8f\n",TOTAL/NR)}' $File`
sdev=`awk -v imean=$mean '{TOTAL+=(imean-$1)^2} END{printf("%.8f",(TOTAL/FNR)^(1/2))}' $File`
echo "eFSA network-based event checking delay: mean:"$mean", standard dev:"$sdev

File="localsensorreading.log"
mean=`awk '{TOTAL+=$1} END{printf("%.8f\n",TOTAL/NR)}' $File`
sdev=`awk -v imean=$mean '{TOTAL+=(imean-$1)^2} END{printf("%.8f",(TOTAL/FNR)^(1/2))}' $File`
echo "eFSA local sensor reading delay: mean:"$mean", standard dev:"$sdev

File="networksensorreading.log"
mean=`awk '{TOTAL+=$1} END{printf("%.8f\n",TOTAL/NR)}' $File`
sdev=`awk -v imean=$mean '{TOTAL+=(imean-$1)^2} END{printf("%.8f",(TOTAL/FNR)^(1/2))}' $File`
echo "eFSA network-based sensor retrieving delay: mean:"$mean", standard dev:"$sdev


