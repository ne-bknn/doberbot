import seaborn as sns
import matplotlib.pyplot as plt

def debug_view(embedded):
    sns.set_theme()
    sns.scatterplot(embedded[:,0], embedded[:,1])
    plt.show()
