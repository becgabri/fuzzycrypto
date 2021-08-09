import sys

def bristolToFrigate(file):
    print("This has not been implemented yet -- check back later!")

fToBGateConv = { 8: "AND", 6: "XOR", 14: "OR", 
}    
def frigateToBristol(file):
    with open(file, "r") as fileObj:
        for idx, line in fileObj:
            all_args = line.strip().split(" ")
            try: 
                first_arg = all_args[0]
                if first_arg == "IN":
                elif first_arg == "OUT":
                elif first_arg == "copy(6)":
                elif first_arg.isdecimal():
                    truth_table = int(first_arg)
                    if truth_table >= 0 and truth_table < 16:
                           
                    else:
                        throw Exception("Truth table is not valid for a gate with two inputs")

def main(converter, file):
    if converter == "toFrigate":
        bristolToFrigate(file)
    else:
        frigateToBristol(file)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Format is python3 {} [toBristol/toFrigate] [file name]".format(sys.argv[0]))
    convert_to = sys.argv[1]
    fname = sys.argv[2]
    if convert_to != "toFrigate" and convert_to != "toBristol":
        print("Format is python3 {} [toBristol/toFrigate]".format(sys.argv[0])) 
    main(convert_to, fname)
