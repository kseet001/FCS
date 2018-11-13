import random


def naiveRandom127():
    generatedNumber = random.randint(0, 254)
    naiveRandom = generatedNumber % 128
    print(naiveRandom)


def main():

    for i in range (0, 511):
        naiveRandom127()


if __name__ == "__main__":
    main()