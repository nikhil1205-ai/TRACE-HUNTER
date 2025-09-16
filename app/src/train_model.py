import numpy as np
import pandas as pd
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import warnings
warnings.filterwarnings('ignore')
import joblib

df = pd.read_csv('data\MalwareMemoryDump.csv')
df = df.drop([
            'pslist_nprocs64bit',
            'handles_nport',
            'psxview_not_in_pslist_false_avg',
            'svcscan_interactive_process_services',
            'callbacks_ngeneric',
            'callbacks_nanonymous',
            'Raw_Type',
            'SubType'
            ],axis=1)

X = df.iloc[:,:-1].values
y = df.iloc[:,-1].values


print(X.shape),print(y.shape)

from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
y = le.fit_transform(y)
print(y)

print("Encoded:", y)
print("Label classes:", le.classes_)

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
X_train, X_test, y_train, y_test = train_test_split(
 X, y, test_size=0.3, random_state=42)
print(X_train.shape)
print(X_test.shape)
print(y_train.shape)
sc=StandardScaler()
X_train=sc.fit_transform(X_train)
X_test=sc.transform(X_test)

# joblib.dump(sc, 'StandardScaler.pkl')

from sklearn.ensemble import RandomForestClassifier, AdaBoostClassifier, GradientBoostingClassifier,BaggingClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.naive_bayes import GaussianNB,BernoulliNB
from sklearn.metrics import accuracy_score, classification_report,ConfusionMatrixDisplay, \
                            precision_score, recall_score, f1_score, roc_auc_score,roc_curve,confusion_matrix

def classalgo_test(x_train,x_test,y_train,y_test): #classification


    dc=DecisionTreeClassifier()
    rfc=RandomForestClassifier()
    gbc=GradientBoostingClassifier()
    Bagging=BaggingClassifier()
    AdaBoost=AdaBoostClassifier()

    algos = [dc,rfc,gbc,Bagging,AdaBoost]
    algo_names = ['DecisionTreeClassifier','RandomForestClassifier','GradientBoostingClassifier','BaggingClassifier','XGBClassifier','AdaBoostClassifier']
    Train_acc=[]
    Train_precsc=[]
    Train_fsc=[]
    Train_Recall=[]
    Test_acc=[]
    Test_precsc=[]
    Test_fsc=[]
    Test_Recall=[]
    Test_AUC=[]

    result = pd.DataFrame(index = algo_names)

    for algo in algos:

        algo.fit(x_train,y_train)
        y_train_pred = algo.predict(x_train)
        y_test_pred = algo.predict(x_test)
        Train_acc.append(accuracy_score(y_train,y_train_pred))
        Train_precsc.append(precision_score(y_train,y_train_pred))
        Train_fsc.append(f1_score(y_train,y_train_pred))
        Train_Recall.append(recall_score(y_train,y_train_pred,average='micro'))


        Test_acc.append(accuracy_score(y_test,y_test_pred))
        Test_precsc.append(precision_score(y_test,y_test_pred))
        Test_fsc.append(f1_score(y_test,y_test_pred))
        Test_Recall.append(recall_score(y_test,y_test_pred,average='micro'))
        Test_AUC.append(roc_auc_score(y_test,y_test_pred))


    result['Train_Accuracy Score'] = Train_acc
    result['Train_Precision Score'] = Train_precsc
    result['Train_F1Score']= Train_fsc
    result['Train_Recall']= Train_Recall
    result['Test_Accuracy Score'] = Test_acc
    result['Test_Precision Score'] = Test_precsc
    result['Test_F1Score']= Test_fsc
    result['Test_Recall']= Test_Recall
    result['Test_AUC_Score']= Test_AUC

    return result.sort_values('Test_Accuracy Score', ascending=False)

classalgo_test(X_train,X_test,y_train,y_test)

rf=RandomForestClassifier()
rf.fit(X_train,y_train)

RandomForestClassifier
RandomForestClassifier()
rf_predict=rf.predict(X_test)
print(confusion_matrix(y_test,rf_predict))


# joblib.dump(rf, 'random_forest_model.pkl')

# loaded_model = joblib.load('/content/random_forest_model.pkl')
# scale = joblib.load('/content/StandardScaler.pkl')







