// Setup firebase-admin for use in nodejs
// 1- Add the firebase-admin npm package.
// 2- Go to https://console.firebase.google.com/ and create a project if you do not have an existing one. And take note of the project ID .
// 3- Get the secret JSON file from https://console.firebase.google.com/u/0/project/{YOUR_PROJECT_ID}/settings/serviceaccounts/adminsdk.
// 4- Set the GOOGLE_APPLICATION_CREDENTIALS environment variable to equal the path of the service account JSON file.
// 5- import the library using`import * as admin from 'firebase-admin'` in the server file.
// 6- Call `admin.initializeApp()` in the server file to establish the connection. Make sure that it is called only once.

// If you need help please reach out to @hadyrashwan on Github or  @h2rashwan on twitter.

const admin = require('firebase-admin');

const db = admin.firestore();

/**
 * Use the library with Google's Firestore database
 *
 * @class FirestoreAdapter
 */
class FirestoreAdapter {
  name;
  undefinedFirestoreValue = 'custom.type.firestore'; // A work around as firestore does not support undefined.
  namePrefix = 'oidc_library';
  constructor(name) {
    this.name = `${this.namePrefix}_${name.split(' ').join('_')}`;
  }

  async upsert(id, payload, expiresIn) {
    let expiresAt;

    if (expiresIn) {
      expiresAt = new Date(Date.now() + expiresIn * 1000);
    }

    await db
      .collection(this.name)
      .doc(id)
      .set(
        {
          payload: this.updateNestedObject(
            payload,
            undefined,
            this.undefinedFirestoreValue
          ),
          ...(expiresAt ? { expiresAt } : null)
        },
        { merge: true }
      );
  }
  async find(id) {
    const response = await db
      .collection(this.name)
      .doc(id)
      .get();

    if (!response.exists) {
      return undefined;
    }
    const data = response.data();
    return this.updateNestedObject(
      data.payload,
      this.undefinedFirestoreValue,
      undefined
    );
  }
  async findByUserCode(userCode) {
    const response = await db
      .collection(this.name)
      .where('payload.userCode', '==', userCode)
      .limit(1)
      .get();

    if (response.empty) {
      return undefined;
    }
    const data = response[0].data();
    return this.updateNestedObject(
      data.payload,
      this.undefinedFirestoreValue,
      undefined
    );
  }

  async findByUid(uid) {
    const response = await db
      .collection(this.name)
      .where('payload.uid', '==', uid)
      .limit(1)
      .get();

    if (response.empty) {
      return undefined;
    }
    const data = response.docs[0].data();
    return this.updateNestedObject(
      data.payload,
      this.undefinedFirestoreValue,
      undefined
    );
  }
  async destroy(id) {
    await db
      .collection(this.name)
      .doc(id)
      .delete();
  }
  async revokeByGrantId(grantId) {
    const response = await db
      .collection(this.name)
      .where('payload.grantId', '==', grantId)
      .get();
    for (const doc of response.docs) {
      await db
        .collection(this.name)
        .doc(doc.id)
        .delete();
    }
  }
  async consume(id) {
    const response = await db
      .collection(this.name)
      .doc(id)
      .get();
    if (!response.exists) {
      return;
    }
    const payload = response.data();
    payload['consumed'] = Math.floor(Date.now() / 1000);

    await db
      .collection(this.name)
      .doc(id)
      .update(payload);
  }
  /**
   * Replace a value in the object with another value
   *
   * @private
   * @param {object} object
   * @param {(string | undefined)} value
   * @param {(string | undefined)} toReplaceValue
   * @returns
   * @memberof FirestoreAdapter
   */
  updateNestedObject(object, value, toReplaceValue) {
    for (const key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        if (object[key] === value) {
          object[key] = toReplaceValue;
          continue;
        }
        if (typeof object[key] === 'object') {
          // Recursion
          object[key] = this.updateNestedObject(
            object[key],
            value,
            toReplaceValue
          );
        }
      }
    }
    return object;
  }
}

module.exports = FirestoreAdapter;
