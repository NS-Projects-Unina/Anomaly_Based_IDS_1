import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Carica i dataset di training e test
train_data = pd.read_csv('machineLearning/Train_data.csv')
test_data = pd.read_csv('machineLearning/Test_data.csv')

# Prepara le feature e il target per il training set
X_train = train_data.drop('class', axis=1)
y_train = train_data['class']

# Prepara le feature per il test set (senza target)
X_test = test_data

# Codifica one-hot per le colonne categoriche
X_train = pd.get_dummies(X_train)
X_test = pd.get_dummies(X_test)

# Allinea le colonne di X_test con quelle di X_train
X_test = X_test.reindex(columns=X_train.columns, fill_value=0)

# Inizializza e addestra il modello
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Salva il modello addestrato
joblib.dump(model, 'machineLearning/modello_addestrato.joblib')

# Fai previsioni sul test set
y_pred = model.predict(X_test)

# Stampa le previsioni
print('Predizioni:', y_pred)