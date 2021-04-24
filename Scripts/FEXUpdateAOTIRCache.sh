#!/bin/bash
FEX={$1:FEXLoader}
FEX=`which "$FEX"`
FEX=`realpath Bin/FEXLoader`
FILES=""
for fileid in ~/.fex-emu/aotir/*.path; do
	filename=`cat "$fileid"`
	if [ -f "${fileid%.path}.aotir" ]; then
		echo "$filename has already been generated"
	else
		echo "Will process $filename ($fileid)"
		FILES="$filename
$FILES"
	fi
done

parallel $FEX --aotirgenerate {} <<< $FILES
