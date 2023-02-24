import matplotlib.pyplot as plt  # Add support for drawing figures
import reader as rd  # Loads traces
import numpy as np

def plot_trace(input_path: str, save: bool):
    """
    trace: The trace to plot
    save: optional; Set to True to save the plot on disk instead of showing in window
    """
    title='Power trace'
    filename='power_trace.png'
    # Load measured traces into a matrix: trace-number x trace-length
    reader = rd.DPAReader(input_path)
    trace = reader.traces[0]
    
    if len(trace.shape) == 2:
        num_samples = trace.shape[1]
    else:
        num_samples = len(trace)


        []
    plt.figure()
    plt.plot(trace, lw=.5)
    plt.xlabel('Samples')
    plt.xlim(0, num_samples)
    plt.ylabel('Power Consumption')
    if trace.dtype == "uint8":
        plt.ylim(0, 255)
    plt.grid('on')
    plt.title(title)
    if save:
        plt.savefig(filename, format='png')
        plt.close()
    else:
        plt.show()

def plot_key_byte(kb, key, corr_vector, block=True, save=False):
    """
    kb: The key byte in range 0..15
    key: The value of the key byte (range: 0..255)
    corr_vector: Correlations for key byte at sample points 
        (length: #samples)
    block: Set to False to avoid blocking the main thread. Be aware 
        that you have to keep the main thread alive after you finished 
        all plots e.g. by calling the wait_for_plots() function in the very end.
        Also be patient, loading all plots may take some time
    save: optional; Set to True to save the plot on disk instead of showing in window
    """
    # Plot correlation for given key byte
    plt.figure()
    plt.xlabel('Samples')
    plt.xlim(0, len(corr_vector))
    plt.ylabel('Correlation')
    plt.ylim(-1, 1)
    plt.grid('on')
    plt.title('Correlation for key byte {} (key = 0x{:02X})'.format(kb, key))
    plt.plot(corr_vector, lw=.5)
    if save:
        plt.savefig('key_byte_{}.png'.format(kb), format='png')
        plt.close()
    else:
        plt.show(block=block)


def plot_key_hypothesis(kb, corr_matrix, key=None, block=True, save=False):
    """
    kb: The key byte in range 0..15
    corr_matrix: Correlations for key hypothesis at sample points 
        (dimension: #hypothesis x #samples)
    key: The correct key for visual highlighting
    block: Set to False to avoid blocking the main thread. Be aware 
        that you have to keep the main thread alive after you finished 
        all plots e.g. by calling the wait_for_plots() function in the very end.
        Also be patient, loading all plots may take some time
    save: optional; Set to True to save the plot on disk instead of showing in window
    """
    # Plot correlation for all key hypothesis
    plt.figure()
    plt.xlabel('Samples')
    plt.xlim(0, corr_matrix.shape[1])
    plt.ylabel('Correlation')
    plt.ylim(-1, 1)
    plt.grid('on')
    plt.title('Correlation for key byte {}'.format(kb))
    if key != None:
        for i in range(corr_matrix.shape[0]):
            plt.plot(corr_matrix[i], '#CCCCCC', lw=.5)
        plt.plot(corr_matrix[key], '#000000', lw=.5)
    else:
        for i in range(corr_matrix.shape[0]):
            plt.plot(corr_matrix[i], lw=.5)
    if save:
        plt.savefig('key_hypothesis_{}.png'.format(kb), format='png')
        plt.close()
    else:
        plt.show(block=block)


def plot_max_correlation(num_traces, max_corr, key=None, save=False, byte=0):
    """
    num_traces: Vector of used number of traces (e.g. [10, 50, 100])
    max_corr: Max correlation for every key hypothesis and used number of traces
        (dimension: len(num_traces) x #hypothesis)
    key: The correct key for visual highlighting
    save: optional; Set to True to save the plot on disk instead of showing in window
    byte: number of the byte (for the filename only)
    """
    # Use absolute values for max correlation
    max_corr = np.absolute(max_corr)

    # Plot correlation for all key hypothesis
    plt.figure()
    plt.xlabel('Number of traces')
    plt.xlim(num_traces[0], num_traces[-1])
    plt.ylabel('Max-Abs Correlation')
    plt.ylim(0, 1)
    plt.grid('on')
    plt.title('Key byte {}'.format(byte))
    if key == None:
        key = np.argmax(max_corr[-1, :])
    for i in range(max_corr.shape[1]):
        plt.plot(num_traces, max_corr[:, i], '#CCCCCC', lw=.5)
    plt.plot(num_traces, max_corr[:, key], '#000000', lw=1)
    if save:
        plt.savefig('max_correlation_%.2i.png' % byte, format='png')
        plt.close()
    else:
        plt.show()

def wait_for_plots():
    """
    Use this method in conjunction with the other print functions when 'block=False' 
    to block the main thread in the end for interactivity with the plots.
    """
    plt.show()
