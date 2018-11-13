import random
import matplotlib
import matplotlib.pyplot as plt
import numpy as np

s = [None]

def naiveRandom127():
    generatedNumber = random.randint(0, 254)
    naiveRandom = generatedNumber % 128
    return naiveRandom

def plotGraph(s):
    t = np.arange(0, 512, 1)
    fig, ax = plt.subplots()
    ax.plot(s, t)

    ax.set(xlabel='Random', ylabel='attempt',
           title='Naive Random Distribution')
    ax.grid()

    fig.savefig("test.png")
    plt.show()

# def plotHistogram(s):
#     plt.hist(s, bins=int(512))
#     fig=matplotlib.pyplot.gcf()
#     fig.savefig("test2.png")

def main():
    for i in range(1, 512):
        s.append(naiveRandom127())

    print(str(s))

    plotGraph(s)
    #plotHistogram(s)

if __name__ == "__main__":
    main()

