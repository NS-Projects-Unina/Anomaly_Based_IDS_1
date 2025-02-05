import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Carica i dataset di training e test
train_data = pd.read_csv('machineLearning/train_net.csv')
test_data = pd.read_csv('machineLearning/test_net.csv')

# Converti i nomi delle colonne in maiuscolo
train_data.columns = train_data.columns.str.upper()
test_data.columns = test_data.columns.str.upper()

# Escludi le variabili non desiderate
columns_to_exclude = ['FIRST_SWITCHED', 'FLOW_DURATION_MILLISECONDS', 'LAST_SWITCHED', 'PROTOCOL', 'ID']
train_data = train_data.drop(columns=columns_to_exclude)
test_data = test_data.drop(columns=columns_to_exclude)

# Prepara le feature e il target per il training set
X_train = train_data.drop('ALERT', axis=1)
y_train = train_data['ALERT']

# Prepara le feature per il test set (senza target)
X_test = test_data.drop('ALERT', axis=1, errors='ignore')

# Gestisci i valori NaN nelle feature
X_train = X_train.fillna(X_train.mean(numeric_only=True)).fillna('MISSING')
X_test = X_test.fillna(X_test.mean(numeric_only=True)).fillna('MISSING')

# Gestisci i valori NaN nel target
y_train = y_train.fillna(y_train.mode()[0])

# Limita il numero di variabili dummy
def limit_dummies(df, max_categories=10):
    for col in df.select_dtypes(include=['object', 'category']).columns:
        top_categories = df[col].value_counts().index[:max_categories]
        df[col] = df[col].apply(lambda x: x if x in top_categories else 'OTHER')
    return pd.get_dummies(df)

X_train = limit_dummies(X_train)
X_test = limit_dummies(X_test)

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