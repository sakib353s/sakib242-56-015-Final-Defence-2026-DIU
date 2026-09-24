import { useNavigation } from '@react-navigation/native';
import type { NativeStackNavigationProp } from '@react-navigation/native-stack';

import type { RootStackParamList } from './types';

export type Nav = NativeStackNavigationProp<RootStackParamList>;

export function useNav(): Nav {
  return useNavigation<Nav>();
}
