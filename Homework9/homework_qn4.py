import random
import matplotlib.pyplot as plt
import matplotlib
import numpy as np
import plotly.plotly as py
import plotly.tools as tls

s = []

def naiveRandom127():
    generatedNumber = random.getrandbits(8)
    naiveRandom = generatedNumber % 128
    return naiveRandom

def plotHistogram(s):
    plt.hist(s, bins=512)
    plt.title("Naive Random Generator")
    plt.ylabel('Frequency')
    plt.xlabel('Numbers')
    plt.figure(figsize=(2, 3))
    plt.show()

def main():
    for i in range(0, 512):
        s.append(naiveRandom127())

    print(s)
    #plotGraph(s)
    plotHistogram(s)

if __name__ == "__main__":
    main()


# def plotGraph(s):
#     t = np.arange(0, 512, 1)
#     fig, ax = plt.subplots()
#     ax.plot(s, t)
#
#     ax.set(xlabel='Random', ylabel='attempt',
#            title='Naive Random Distribution')
#     ax.grid()
#
#     fig.savefig("test.png")
#     plt.show()
