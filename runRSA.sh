#!/bin/bash
#!/usr/bin/python

ARRALG=("bf" "ff" "knj" "pp" "pr")
ARR0=(6 6 6 6 6)
ARR0U=(52 54 52 52 68)
ARR1S=(54 56 54 54 70)
ARR1U=(58 58 58 58 82)
ARR10S=(60 60 60 60 84)
ARR10U=(66 66 66 66 94)

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
