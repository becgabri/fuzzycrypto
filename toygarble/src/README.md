# Usage instructions

## Building

``go build -o garbler`` 

## To test evaluate a circuit (does not involve garbling)!

``./garbler test-circuit ../circuits/aes_128.txt 0 0``

## To garble an input circuit. Output is garbled circuit and labels.

``./garbler garble ../circuits/aes_128.txt ./test.garble ./test.lab``

## To *test* evaluate the garbled circuit on concrete inputs (requires all input labels)

``./garbler evaluate-test ../circuits/aes_128.txt ./test.garble ./test.lab 0 0``

