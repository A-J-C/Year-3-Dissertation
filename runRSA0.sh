#!/bin/bash
#!/usr/bin/python

ARRALG=("qs")
ARR0=(6)
ARR0U=(30)
ARR1S=(32)
ARR1U=(48)
ARR10S=(50)
ARR10U=(60)

num=25000

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_RSA.py -s RSA_results_"$i"_1S -$i -l ${ARR0[$j]} -u ${ARR0U[$j]} -n $num"

    echo $i

    cp rsaResults.slurm rsaResults"$i"1S.slurm

    echo $params >> rsaResults"$i"1S.slurm

    sbatch rsaResults"$i"1S.slurm
    ((j++))
done

num=5000

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_RSA.py -s RSA_results_"$i"_10S -$i -l ${ARR1S[$j]} -u ${ARR1U[$j]} -n $num"

    echo $i

    cp rsaResults.slurm rsaResults"$i"10S.slurm

    echo $params >> rsaResults"$i"10S.slurm

    sbatch rsaResults"$i"10S.slurm
    ((j++))
done

num=1000

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_RSA.py -s RSA_results_"$i"_1M -$i -l ${ARR10S[$j]} -u ${ARR10U[$j]} -n $num"

    echo $i

    cp rsaResults.slurm rsaResults"$i"1M.slurm

    echo $params >> rsaResults"$i"1M.slurm

    sbatch rsaResults"$i"1M.slurm
    ((j++))
done
