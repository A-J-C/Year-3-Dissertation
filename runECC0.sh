#!/bin/bash
#!/usr/bin/python

ARRALG=("ma")
ARR0=(3)
ARR0U=(20)
ARR1S=(21)
ARR1U=(40)
ARR10S=(41)
ARR10U=(56)

num=25000

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_ECC.py -s ECC_results_"$i"_1S -$i -l ${ARR0[$j]} -u ${ARR0U[$j]} -n $num"

    echo $i

    cp eccResults.slurm eccResults"$i"1S.slurm

    echo $params >> eccResults"$i"1S.slurm

    sbatch eccResults"$i"1S.slurm
    ((j++))
done

num=25000

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_ECC.py -s ECC_results_"$i"_10S -$i -l ${ARR1S[$j]} -u ${ARR1U[$j]} -n $num"

    echo $i

    cp eccResults.slurm eccResults"$i"10S.slurm

    echo $params >> eccResults"$i"10S.slurm

    sbatch eccResults"$i"10S.slurm
    ((j++))
done

num=25000

j=0
for i in "${ARRALG[@]}"
do
    params="python3 results_ECC.py -s ECC_results_"$i"_1M -$i -l ${ARR10S[$j]} -u ${ARR10U[$j]} -n $num"

    echo $i

    cp eccResults.slurm eccResults"$i"1M.slurm

    echo $params >> eccResults"$i"1M.slurm

    sbatch eccResults"$i"1M.slurm
    ((j++))
done
