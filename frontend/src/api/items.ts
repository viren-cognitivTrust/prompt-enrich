import { apiClient } from "./client";

export interface Item {
  id: number;
  owner_id: string;
  title: string;
  content?: string | null;
  created_at: string;
  updated_at: string;
}

export interface ItemCreate {
  title: string;
  content?: string;
}

export interface ItemUpdate {
  title?: string;
  content?: string;
}

export async function listItems(): Promise<Item[]> {
  const { data } = await apiClient.get<Item[]>("/items");
  return data;
}

export async function createItem(payload: ItemCreate): Promise<Item> {
  const { data } = await apiClient.post<Item>("/items", payload);
  return data;
}

export async function updateItem(id: number, payload: ItemUpdate): Promise<Item> {
  const { data } = await apiClient.put<Item>(`/items/${id}`, payload);
  return data;
}

export async function deleteItem(id: number): Promise<void> {
  await apiClient.delete(`/items/${id}`);
}


