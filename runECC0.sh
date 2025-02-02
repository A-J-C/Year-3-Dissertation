#!/bin/bash
#!/usr/bin/python

ARRALG=("ma ph")
ARR0=(3 10)
ARR0U=(20 20)


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


