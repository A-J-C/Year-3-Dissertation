#!/bin/bash
#!/usr/bin/python

ARRALG=("bf" "bs" "pl" "pr" "ph")
ARR0=(3 3 3 3 3)
ARR1S=(18 26 18 28 40)
ARR10S=(22 32 20 32 52)
ARR1M=(24 34 22 34 56)

num=25000

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_ECC.py -s ECC_results_"$i"_1S -$i -l ${ARR0[$j]} -u ${ARR1S[$j]} -n $num"

    echo $i

    cp eccResults.slurm eccResults"$i"1S.slurm

    echo $params >> eccResults"$i"1S.slurm

    sbatch eccResults"$i"1S.slurm
    ((j++))
done

num=2500

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_ECC.py -s ECC_results_"$i"_10S -$i -l ${ARR1S[$j]} -u ${ARR10S[$j]} -n $num"

    echo $i

    cp eccResults.slurm eccResults"$i"10S.slurm

    echo $params >> eccResults"$i"10S.slurm

    sbatch eccResults"$i"10S.slurm
    ((j++))
done

num=250

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_ECC.py -s ECC_results_"$i"_1M -$i -l ${ARR10S[$j]} -u ${ARR1M[$j]} -n $num"

    echo $i

    cp eccResults.slurm eccResults"$i"1M.slurm

    echo $params >> eccResults"$i"1M.slurm

    sbatch eccResults"$i"1M.slurm
    ((j++))
done
