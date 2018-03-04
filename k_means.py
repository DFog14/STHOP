import json
import ipaddress
import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
from sklearn.cluster import KMeans

TLS_Key = {"TLSv1.2" : 2, "TLSv1.1" : 1, "TLSv1" : 0}
Cipher_Key = {
    'ECDHE-RSA-AES128-GCM-SHA256' : 0,
    'ECDHE-ECDSA-AES128-GCM-SHA256' : 1,
    'ECDHE-ECDSA-AES256-GCM-SHA384' : 2,
    'AES128-GCM-SHA256' : 3,
    'ECDHE-RSA-AES256-SHA384' : 4,
    'ECDHE-RSA-AES256-GCM-SHA384' : 5,
    'AES256-SHA256' : 6,
    'ECDHE-RSA-AES128-SHA256' : 7,
    'DHE-RSA-AES256-GCM-SHA384' : 8,
    'AES128-SHA' : 9,
    'DHE-RSA-AES128-SHA' : 10,
    'AES256-GCM-SHA384' : 11,
    'AES256-SHA' : 12,
    'ECDHE-RSA-AES128-SHA' : 13,
    'DHE-RSA-AES256-SHA' : 14,
    'AES128-SHA256' : 15,
    'ECDHE-RSA-AES256-SHA' : 16,
    'DHE-RSA-AES128-GCM-SHA256' : 17,
    'DHE-RSA-AES256-SHA256' : 18,
    'CAMELLIA256-SHA' : 19,
    'DHE-RSA-CAMELLIA256-SHA' : 20,
    'DHE-RSA-AES128-SHA256' : 21,
    'ECDHE-ECDSA-AES128-SHA' : 22
}

#remove null and None entries. They break enumeration of the json data.
def removeNone(in_file):
    count = 0
    with open(in_file, 'r') as f:
        json_data = json.loads(f.read())
        for item in json_data:
            if item is 'null' or item is None:
                del json_data[count]
            count = count + 1
    return json_data

#See that Cipher_Key at the top, use this to generate it.
def unique_cipher(json_data):
    l = {}
    count = 0
    for i, j in enumerate(json_data):
        try:
            if json_data[i]['ciphersuite'] not in l:
                l[json_data[i]['ciphersuite']] = count
                count = count + 1
        except:
            continue
    #This print statment will format the dict if you ">" the output to a txt file.
    for key,value in l.items():
        print("'" + key +"'" + ' : ' + str(value) + ',')

#Returns numpy array for k-means equation. Col 0 is cipher. Col 1 is int representaion of ipv4.
#Col 2 is TLS version.
def array_generator(json_data):
    rows = len(json_data)
    sort_vectors = np.zeros((rows, 3))
    for i, j in enumerate(json_data):
        try:
            cipher = Cipher_Key[json_data[i]['ciphersuite']]
        except:
            continue

        try:
            ip = int(ipaddress.IPv4Address(json_data[i]['ip_address']))
        except:
            ip = 0

        version = TLS_Key[json_data[i]['version']]
        sort_vectors[i,0] = cipher
        sort_vectors[i,1] = ip
        sort_vectors[i,2] = version
    return sort_vectors

def cipher_histogram_generator(in_array):
    fig = plt.figure(5)
    plt.hist(in_array[:, 0], bins=np.arange(min(in_array[:, 0]), max(in_array[:, 0]) + 1, 1))
    plt.xlabel('Cipher Suite(Numerically Keyed)')
    plt.ylabel('# of Domains per Cipher')
    plt.show()

#Not sure what to think about this plot. Centers seem oddly places
def k_means_cluster2D(in_array):
    np.random.seed(200)

    K = KMeans(n_clusters=3)
    K.fit(in_array[:, [0, 2]]);
    labels = K.predict(in_array[:, [0, 2]])
    centers = K.cluster_centers_

    fig = plt.figure(6)
    colmap = {1: 'r', 2: 'g', 3: 'b'}
    colors = map(lambda x: colmap[x+1], labels)
    plt.scatter(in_array[:,0], in_array[:,2],  alpha=0.5, edgecolor='k')

    for idx, center in enumerate(centers):
        plt.scatter(*center, color = colmap[idx+1])
    plt.xlim(0, 22)
    plt.ylim(0, 2)
    plt.xlabel('Cipher Suite(Numerically Keyed)')
    plt.ylabel('TLS Version(Numerically Keyed)')
    plt.show()

def k_means_cluster(in_array):
    np.random.seed(5)
    fignum = 1
    titles = ['8 cluster', '3 cluster', '3 cluster, bad init']
    estimators = [('k_means_iris_8', KMeans(n_clusters=8)),
                  ('k_means_iris_3', KMeans(n_clusters=3)),
                  ('k_means_iris_bad_init', KMeans(n_clusters=3, n_init=1, init='random'))]
    for name, est in estimators:
        fig = plt.figure(fignum, figsize=(4,3))
        ax = Axes3D(fig)
        est.fit(in_array)
        labels = est.labels_

        ax.scatter(in_array[:, 0 ], in_array[:, 1], in_array[:, 2], c=labels.astype(np.float), edgecolor='k')
#        ax.w_xaxis.set_ticklabels([0, 22])
#        ax.w_yaxis.set_ticklabels([])
        ax.w_zaxis.set_ticklabels([0, 1, 2])
        ax.set_xlabel('Cipher')
        ax.set_ylabel('IPv4')
        ax.set_zlabel('Version')
        ax.set_title(titles[fignum - 1])
        ax.dist = 12
        fignum = fignum + 1

    fig = plt.figure(fignum, figsize=(4, 3))
    ax = Axes3D(fig, rect=[0, 0, .95, 1], elev=48, azim=134)
    ax.set_xlim(0, 22)
    ax.set_zlim(0, 1)
    plt.show()

def main():
    json_data = removeNone('malicious_output.json')
    #unique_cipher(json_data)
    arr = array_generator(json_data)
    k_means_cluster2D(arr)
    #cipher_histogram_generator(arr)

    #These prints outs give the predicted centers for euclidan distance,
    K = KMeans(n_clusters=3)
    print(K.fit(arr))
    print("labels: {}".format(K.predict(arr)))
    print("centroids: {}".format(K.cluster_centers_))

if __name__ == '__main__':
    main() 

