// This adapter is written in Typescript. If you want to get Javascript version without compiling it with tsc, paste this code here: https://babeljs.io/en/repl (choose Typescript preset)

// The filename is suffixed with 'gsi' because this adapter makes use of Global Secondary Indexes.

/**
 * Prerequisites:
 * 
 * 1. Create a DynamoDB Table with following details:
 *        Partition Key: modelId
 *        TTL Attribute: expiresAt
 *        Three Global Secondary Indexes:
 *            GSI 1:
 *                Index Name: uidIndex
 *                Partition Key: uid
 *            GSI 2:
 *                Index Name: grantIdIndex
 *                Partition Key: grantId
 *            GSI 3:
 *                Index Name: userCodeIndex
 *                Partition Key: userCode
 * 
 * 2. Put the Table's name in environment variable OAUTH_TABLE or simply replace the value of constant TABLE_NAME below.
 * 
 * 3. You'll also need to change value of TABLE_REGION constant below if you aren't in AWS compute environment or if DynamoDB Table exists in different region.
 * 
 * 4. If you are in AWS' compute environment, nothing more needs to be changed in code.
 *    You just need to give proper IAM permissions of DynamoDB Table.
 *    Required Permissions:
 *        dynamodb:GetItem
 *        dynamodb:ConditionCheckItem
 *        dynamodb:UpdateItem
 *        dynamodb:DeleteItem
 *        dynamodb:Query
 *        dynamodb:BatchWriteItem
 *    If you aren't in AWS' compute environment, you'll also need to configure SDK with proper credentials.
 *    @see https://docs.aws.amazon.com/sdk-for-javascript/v2/developer-guide/configuring-the-jssdk.html
 */  

// Author: Sachin Shekhar <https://github.com/SachinShekhar>
// Mention @SachinShekhar in issues to ask questions about this code.

import { Adapter, AdapterPayload } from "oidc-provider";
import { DynamoDB } from "aws-sdk";

const TABLE_NAME = process.env.OAUTH_TABLE!;
const TABLE_REGION = process.env.AWS_REGION;

const dynamoClient = new DynamoDB.DocumentClient({
  region: TABLE_REGION,
});

export class DynamoDBAdapter implements Adapter {
  name: string;

  constructor(name: string) {
    this.name = name;
  }

  async upsert(id: string, payload: AdapterPayload, expiresIn?: number): Promise<void> {
    // DynamoDB can recognise TTL values only in seconds
    const expiresAt = expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null;

    const params: DynamoDB.DocumentClient.UpdateItemInput = {
      TableName: TABLE_NAME,
      Key: { modelId: this.name + "-" + id },
      UpdateExpression:
        "SET payload = :payload" +
        (expiresAt ? ", expiresAt = :expiresAt" : "") +
        (payload.userCode ? ", userCode = :userCode" : "") +
        (payload.uid ? ", uid = :uid" : "") +
        (payload.grantId ? ", grantId = :grantId" : ""),
      ExpressionAttributeValues: {
        ":payload": payload,
        ...(expiresAt ? { ":expiresAt": expiresAt } : {}),
        ...(payload.userCode ? { ":userCode": payload.userCode } : {}),
        ...(payload.uid ? { ":uid": payload.uid } : {}),
        ...(payload.grantId ? { ":grantId": payload.grantId } : {}),
      },
    };

    await dynamoClient.update(params).promise();
  }

  async find(id: string): Promise<AdapterPayload | undefined> {
    const params: DynamoDB.DocumentClient.GetItemInput = {
      TableName: TABLE_NAME,
      Key: { modelId: this.name + "-" + id },
      ProjectionExpression: "payload, expiresAt",
    };

    const result = <{ payload: AdapterPayload; expiresAt?: number } | undefined>(
      (await dynamoClient.get(params).promise()).Item
    );

    // DynamoDB can take upto 48 hours to drop expired items, so a check is required
    if (!result || (result.expiresAt && Date.now() > result.expiresAt * 1000)) {
      return undefined;
    }

    return result.payload;
  }

  async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
    const params: DynamoDB.DocumentClient.QueryInput = {
      TableName: TABLE_NAME,
      IndexName: "userCodeIndex",
      KeyConditionExpression: "userCode = :userCode",
      ExpressionAttributeValues: {
        ":userCode": userCode,
      },
      Limit: 1,
      ProjectionExpression: "payload, expiresAt",
    };

    const result = <{ payload: AdapterPayload; expiresAt?: number } | undefined>(
      (await dynamoClient.query(params).promise()).Items?.[0]
    );

    // DynamoDB can take upto 48 hours to drop expired items, so a check is required
    if (!result || (result.expiresAt && Date.now() > result.expiresAt * 1000)) {
      return undefined;
    }

    return result.payload;
  }

  async findByUid(uid: string): Promise<AdapterPayload | undefined> {
    const params: DynamoDB.DocumentClient.QueryInput = {
      TableName: TABLE_NAME,
      IndexName: "uidIndex",
      KeyConditionExpression: "uid = :uid",
      ExpressionAttributeValues: {
        ":uid": uid,
      },
      Limit: 1,
      ProjectionExpression: "payload, expiresAt",
    };

    const result = <{ payload: AdapterPayload; expiresAt?: number } | undefined>(
      (await dynamoClient.query(params).promise()).Items?.[0]
    );

    // DynamoDB can take upto 48 hours to drop expired items, so a check is required
    if (!result || (result.expiresAt && Date.now() > result.expiresAt * 1000)) {
      return undefined;
    }

    return result.payload;
  }

  async consume(id: string): Promise<void> {
    const params: DynamoDB.DocumentClient.UpdateItemInput = {
      TableName: TABLE_NAME,
      Key: { modelId: this.name + "-" + id },
      UpdateExpression: "SET #payload.#consumed = :value",
      ExpressionAttributeNames: {
        "#payload": "payload",
        "#consumed": "consumed",
      },
      ExpressionAttributeValues: {
        ":value": Math.floor(Date.now() / 1000),
      },
      ConditionExpression: "attribute_exists(modelId)",
    };

    await dynamoClient.update(params).promise();
  }

  async destroy(id: string): Promise<void> {
    const params: DynamoDB.DocumentClient.DeleteItemInput = {
      TableName: TABLE_NAME,
      Key: { modelId: this.name + "-" + id },
    };

    await dynamoClient.delete(params).promise();
  }

  async revokeByGrantId(grantId: string): Promise<void> {
    let ExclusiveStartKey: DynamoDB.DocumentClient.Key | undefined = undefined;

    do {
      const params: DynamoDB.DocumentClient.QueryInput = {
        TableName: TABLE_NAME,
        IndexName: "grantIdIndex",
        KeyConditionExpression: "grantId = :grantId",
        ExpressionAttributeValues: {
          ":grantId": grantId,
        },
        ProjectionExpression: "modelId",
        Limit: 25,
        ExclusiveStartKey,
      };

      const queryResult = await dynamoClient.query(params).promise();
      ExclusiveStartKey = queryResult.LastEvaluatedKey;

      const items = <{ modelId: string }[] | undefined>queryResult.Items;

      if (!items || !items.length) {
        return;
      }

      const batchWriteParams: DynamoDB.DocumentClient.BatchWriteItemInput = {
        RequestItems: {
          [TABLE_NAME]: items.reduce<DynamoDB.DocumentClient.WriteRequests>(
            (acc, item) => [...acc, { DeleteRequest: { Key: { modelId: item.modelId } } }],
            []
          ),
        },
      };

      await dynamoClient.batchWrite(batchWriteParams).promise();
    } while (ExclusiveStartKey);
  }
}
